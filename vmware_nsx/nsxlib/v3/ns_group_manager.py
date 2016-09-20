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

from oslo_log import log

from vmware_nsx._i18n import _, _LW
from vmware_nsx.nsxlib.v3 import exceptions
from vmware_nsx.nsxlib.v3 import nsx_constants as consts


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
    it has strict size limit. To overcome the limited space challenge, we
    create several nested groups instead of just one, and we evenly distribute
    NSGroups (security-groups) between them.
    By using an hashing function on the NSGroup uuid we determine in which
    group it should be added, and when deleting an NSGroup (security-group) we
    use the same procedure to find which nested group it was added.
    """

    NESTED_GROUP_NAME = 'OS Nested Group'
    NESTED_GROUP_DESCRIPTION = ('OpenStack NSGroup. Do not delete.')

    def __init__(self, nsxlib, size):
        self.nsxlib_nsgroup = nsxlib.ns_group
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
            for nsgroup in self.nsxlib_nsgroup.list()
            if self.nsxlib_nsgroup.is_internal_resource(nsgroup)}

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
        tags = self.nsxlib_nsgroup.build_v3_api_version_tag()
        return self.nsxlib_nsgroup.create(name, description, tags)

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
                self.nsxlib_nsgroup.add_members(
                    group, consts.NSGROUP, [nsgroup_id])
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
                self.nsxlib_nsgroup.remove_member(
                    group, consts.NSGROUP,
                    nsgroup_id, verify=True)
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
