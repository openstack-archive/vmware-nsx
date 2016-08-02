# Copyright 2015 OpenStack Foundation

# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import uuid

from oslo_config import cfg
from oslo_log import log

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import utils
from vmware_nsx.nsxlib import v3
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import exceptions


LOG = log.getLogger(__name__)


class NSGroupManager(object):
    """
    This class assists with NSX integration for Neutron security-groups,
    Each Neutron security-group is associated with NSX NSGroup object.
    Some specific security policies are the same across all security-groups,
    i.e - Default drop rule, DHCP. In order to bind these rules to all
    NSGroups (security-groups), we create a nested NSGroup (which its members
    are also of type NSGroups) to group the other NSGroups and associate it
    with these rules.
    In practice, one NSGroup (nested) can't contain all the other NSGroups, as
    it has strict size limit. To overcome the limited space challange, we
    create several nested groups instead of just one, and we evenly distribute
    NSGroups (security-groups) between them.
    By using an hashing function on the NSGroup uuid we determine in which
    group it should be added, and when deleting an NSGroup (security-group) we
    use the same procedure to find which nested group it was added.
    """

    NESTED_GROUP_NAME = 'OS Nested Group'
    NESTED_GROUP_DESCRIPTION = ('OpenStack NSGroup. Do not delete.')

    def __init__(self, size):
        # XXX intergrate this in a better way..
        self.nsx = v3.NsxLib(
            username=cfg.CONF.nsx_v3.nsx_api_user,
            password=cfg.CONF.nsx_v3.nsx_api_password,
            retries=cfg.CONF.nsx_v3.http_retries,
            insecure=cfg.CONF.nsx_v3.insecure,
            ca_file=cfg.CONF.nsx_v3.ca_file,
            concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
            http_timeout=cfg.CONF.nsx_v3.http_timeout,
            http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
            conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
            http_provider=None,
            max_attempts=cfg.CONF.nsx_v3.retries)

        self._nested_groups = self._init_nested_groups(size)
        self._size = len(self._nested_groups)

    @property
    def size(self):
        return self._size

    @property
    def nested_groups(self):
        return self._nested_groups

    def _init_nested_groups(self, requested_size):
        # Construct the groups dict -
        # {0: <groups-1>,.., n-1: <groups-n>}
        size = requested_size
        nested_groups = {
            self._get_nested_group_index_from_name(nsgroup): nsgroup['id']
            for nsgroup in self.nsx.list_nsgroups()
            if utils.is_internal_resource(nsgroup)}

        if nested_groups:
            size = max(requested_size, max(nested_groups) + 1)
            if size > requested_size:
                LOG.warning(_LW("Lowering the value of "
                                "nsx_v3:number_of_nested_groups isn't "
                                "supported, '%s' nested-groups will be used."),
                            size)

        absent_groups = set(range(size)) - set(nested_groups.keys())
        if absent_groups:
            LOG.warning(
                _LW("Found %(num_present)s Nested Groups, "
                    "creating %(num_absent)s more."),
                {'num_present': len(nested_groups),
                 'num_absent': len(absent_groups)})
            for i in absent_groups:
                cont = self._create_nested_group(i)
                nested_groups[i] = cont['id']

        return nested_groups

    def _get_nested_group_index_from_name(self, nested_group):
        # The name format is "Nested Group <index+1>"
        return int(nested_group['display_name'].split()[-1]) - 1

    def _create_nested_group(self, index):
        name_prefix = NSGroupManager.NESTED_GROUP_NAME
        name = '%s %s' % (name_prefix, index + 1)
        description = NSGroupManager.NESTED_GROUP_DESCRIPTION
        tags = utils.build_v3_api_version_tag()
        return self.nsx.create_nsgroup(name, description, tags)

    def _hash_uuid(self, internal_id):
        return hash(uuid.UUID(internal_id))

    def _suggest_nested_group(self, internal_id):
        # Suggests a nested group to use, can be iterated to find alternative
        # group in case that previous suggestions did not help.

        index = self._hash_uuid(internal_id) % self.size
        yield self.nested_groups[index]

        for i in range(1, self.size):
            index = (index + 1) % self.size
            yield self.nested_groups[index]

    def add_nsgroup(self, nsgroup_id):
        for group in self._suggest_nested_group(nsgroup_id):
            try:
                LOG.debug("Adding NSGroup %s to nested group %s",
                          nsgroup_id, group)
                self.nsx.add_nsgroup_members(group,
                                            firewall.NSGROUP,
                                            [nsgroup_id])
                break
            except exceptions.NSGroupIsFull:
                LOG.debug("Nested group %(group_id)s is full, trying the "
                          "next group..", {'group_id': group})
        else:
            raise exceptions.ManagerError(
                details=_("Reached the maximum supported amount of "
                          "security groups."))

    def remove_nsgroup(self, nsgroup_id):
        for group in self._suggest_nested_group(nsgroup_id):
            try:
                self.nsx.remove_nsgroup_member(
                    group, firewall.NSGROUP, nsgroup_id, verify=True)
                break
            except exceptions.NSGroupMemberNotFound:
                LOG.warning(_LW("NSGroup %(nsgroup)s was expected to be found "
                                "in group %(group_id)s, but wasn't. "
                                "Looking in the next group.."),
                            {'nsgroup': nsgroup_id, 'group_id': group})
                continue
        else:
            LOG.warning(_LW("NSGroup %s was marked for removal, but its "
                            "reference is missing."), nsgroup_id)
