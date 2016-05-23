# Copyright 2015 VMware, Inc.  All rights reserved.
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

import logging

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import common_db_mixin as common_db
from neutron.db import securitygroups_db as sg_db

from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import ports
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as v3_utils
from vmware_nsx.shell import resources as shell
from vmware_nsx._i18n import _LE, _LI, _LW
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import security

LOG = logging.getLogger(__name__)


class NeutronSecurityGroupApi(sg_db.SecurityGroupDbMixin,
                              common_db.CommonDbMixin):
    def __init__(self):
        super(NeutronSecurityGroupApi, self)
        self.context = neutron_context.get_admin_context()

    def get_security_groups(self):
        return super(NeutronSecurityGroupApi,
                     self).get_security_groups(self.context)

    def delete_security_group(self, sg_id):
        return super(NeutronSecurityGroupApi,
                     self).delete_security_group(self.context, sg_id)

    def get_nsgroup_id(self, sg_id):
        return nsx_db.get_nsx_security_group_id(
            self.context.session, sg_id)

    def get_port_security_groups(self, port_id):
        secgroups_bindings = self._get_port_security_group_bindings(
            self.context, {'port_id': [port_id]})
        return [b['security_group_id'] for b in secgroups_bindings]

    def get_security_group_ports(self, security_group_id):
        secgroups_bindings = self._get_port_security_group_bindings(
            self.context, {'security_group_id': [security_group_id]})
        return [b['port_id'] for b in secgroups_bindings]


neutron_sg = NeutronSecurityGroupApi()
neutron_db = v3_utils.NeutronDbClient()


@admin_utils.output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    sections = firewall.list_sections()
    LOG.info(formatters.output_formatter(constants.FIREWALL_SECTIONS,
                                         sections, ['display_name', 'id']))
    nsgroups = firewall.list_nsgroups()
    LOG.info(formatters.output_formatter(constants.FIREWALL_NSX_GROUPS,
                                         nsgroups, ['display_name', 'id']))
    return bool(sections) or bool(nsgroups)


@admin_utils.output_header
def nsx_delete_security_groups(resource, event, trigger, **kwargs):
    if 'force' in kwargs and kwargs['force'] is False:
        if nsx_list_security_groups(resource, event, trigger, **kwargs):
            msg = ('Do you want to delete the following NSX firewall '
                   'sections/nsgroups?')
            user_confirm = admin_utils.query_yes_no(msg, default='no')

            if user_confirm is False:
                LOG.info(_LI('NSX security groups cleanup aborted by user'))
                return

    sections = firewall.list_sections()
    # NOTE(roeyc): We use -2 indexing because don't want to delete the
    # default firewall sections.
    if sections:
        NON_DEFAULT_SECURITY_GROUPS = -2
        for section in sections[:NON_DEFAULT_SECURITY_GROUPS]:
            LOG.info(_LI("Deleting firewall section %(display_name)s, "
                         "section id %(id)s"),
                     {'display_name': section['display_name'],
                      'id': section['id']})
            firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
    if nsgroups:
        for nsgroup in [nsg for nsg in nsgroups
                        if not utils.is_internal_resource(nsg)]:
            LOG.info(_LI("Deleting ns-group %(display_name)s, "
                         "ns-group id %(id)s"),
                     {'display_name': nsgroup['display_name'],
                      'id': nsgroup['id']})
            firewall.delete_nsgroup(nsgroup['id'])


@admin_utils.output_header
def neutron_list_security_groups(resource, event, trigger, **kwargs):
    security_groups = neutron_sg.get_security_groups()
    LOG.info(formatters.output_formatter(constants.SECURITY_GROUPS,
                                         security_groups, ['name', 'id']))
    return bool(security_groups)


@admin_utils.output_header
def neutron_delete_security_groups(resource, event, trigger, **kwargs):
    if 'force' in kwargs and kwargs['force'] is False:
        if neutron_list_security_groups(resource, event, trigger, **kwargs):
            msg = ('Do you want to delete the following neutron '
                   'security groups?')
            user_confirm = admin_utils.query_yes_no(msg, default='no')
            if user_confirm is False:
                LOG.info(_LI('Neutron security groups cleanup aborted by '
                             'user'))
                return

    security_groups = neutron_sg.get_security_groups()
    if not security_groups:
        return

    for security_group in security_groups:
        try:
            LOG.info(_LI('Trying to delete %(sg_id)s'),
                     {'sg_id': security_group['id']})
            neutron_sg.delete_security_group(security_group['id'])
            LOG.info(_LI("Deleted security group name: %(name)s id: %(id)s"),
                     {'name': security_group['name'],
                      'id': security_group['id']})
        except Exception as e:
            LOG.warning(str(e))


def _update_ports_dynamic_criteria_tags():
    port_client, _ = ports.get_port_and_profile_clients()
    for port in neutron_db.get_ports():
        secgroups = neutron_sg.get_port_security_groups(port['id'])
        # Nothing to do with ports that are not associated with any sec-group.
        if not secgroups:
            continue

        _, lport_id = neutron_db.get_lswitch_and_lport_id(port['id'])
        lport = port_client.get(lport_id)
        criteria_tags = security.get_lport_tags_for_security_groups(secgroups)
        lport['tags'] = utils.update_v3_tags(
            lport.get('tags', []), criteria_tags)
        port_client._client.update(lport_id, body=lport)


def _update_security_group_dynamic_criteria():
    secgroups = neutron_sg.get_security_groups()
    for sg in secgroups:
        nsgroup_id = neutron_sg.get_nsgroup_id(sg['id'])
        membership_criteria = firewall.get_nsgroup_port_tag_expression(
            security.PORT_SG_SCOPE, sg['id'])
        try:
            # We want to add the dynamic criteria and remove all direct members
            # they will be added by the manager using the new criteria.
            firewall.update_nsgroup(nsgroup_id,
                                    membership_criteria=membership_criteria,
                                    members=[])
        except Exception as e:
            LOG.warning(_LW("Failed to update membership criteria for nsgroup "
                            "%(nsgroup_id)s, request to backend returned "
                            "with error: %(error)s"),
                        {'nsgroup_id': nsgroup_id, 'error': str(e)})


@admin_utils.output_header
def migrate_nsgroups_to_dynamic_criteria(resource, event, trigger, **kwargs):
    if not utils.is_nsx_version_1_1_0(nsxlib.get_version()):
        LOG.error(_LE("Dynamic criteria grouping feature isn't supported by "
                      "this NSX version."))
        return
    # First, we add the criteria tags for all ports.
    _update_ports_dynamic_criteria_tags()
    # Update security-groups with dynamic criteria and remove direct members.
    _update_security_group_dynamic_criteria()


registry.subscribe(nsx_list_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.NSX_LIST.value)

registry.subscribe(neutron_list_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.LIST.value)
registry.subscribe(neutron_list_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.NEUTRON_LIST.value)

registry.subscribe(nsx_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.CLEAN.value)
registry.subscribe(nsx_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.NSX_CLEAN.value)

registry.subscribe(neutron_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.CLEAN.value)
registry.subscribe(neutron_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.NEUTRON_CLEAN.value)
registry.subscribe(migrate_nsgroups_to_dynamic_criteria,
                   constants.FIREWALL_NSX_GROUPS,
                   shell.Operations.MIGRATE_TO_DYNAMIC_CRITERIA.value)
