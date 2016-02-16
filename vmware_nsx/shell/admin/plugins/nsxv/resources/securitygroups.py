# Copyright 2016 VMware, Inc.  All rights reserved.
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
import xml.etree.ElementTree as et

from neutron.callbacks import registry
from neutron import context
from neutron.db import securitygroups_db

from vmware_nsx.db import nsx_models
from vmware_nsx.db import nsxv_models
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import nsxadmin


LOG = logging.getLogger(__name__)


class NeutronSecurityGroupDB(utils.NeutronDbClient):
    def __init__(self):
        super(NeutronSecurityGroupDB, self)
        # FIXME(roeyc): context is already defined in NeutrondDbClient
        self.context = context.get_admin_context()

    def get_security_groups_mappings(self):
        q = self.context.session.query(
            securitygroups_db.SecurityGroup.name,
            securitygroups_db.SecurityGroup.id,
            nsxv_models.NsxvSecurityGroupSectionMapping.ip_section_id,
            nsx_models.NeutronNsxSecurityGroupMapping.nsx_id).join(
                nsxv_models.NsxvSecurityGroupSectionMapping,
                nsx_models.NeutronNsxSecurityGroupMapping).all()
        sg_mappings = [{'name': mapp.name,
                        'id': mapp.id,
                        'section-id': mapp.ip_section_id.split('/')[-1],
                        'nsx-securitygroup-id': mapp.nsx_id}
                       for mapp in q]
        return sg_mappings

    def get_security_groups(self):
        return super(NeutronSecurityGroupDB,
                     self).get_security_groups(self.context)


class NsxFirewallAPI(object):
    def __init__(self):
        self.vcns = utils.get_nsxv_client()

    def list_security_groups(self):
        h, secgroups = self.vcns.list_security_groups()
        root = et.fromstring(secgroups)
        secgroups = []
        for sg in root.iter('securitygroup'):
            sg_id = sg.find('objectId').text
            # This specific security-group is not relevant to the plugin
            if sg_id == 'securitygroup-1':
                continue
            secgroups.append({'name': sg.find('name').text,
                              'id': sg_id})
        return secgroups

    def list_fw_sections(self):
        h, firewall_config = self.vcns.get_dfw_config()
        root = et.fromstring(firewall_config)
        sections = []
        for sec in root.iter('section'):
            sec_id = sec.attrib['id']
            # Don't show NSX default sections, which are not relevant to OS.
            if sec_id in ['1001', '1002', '1003']:
                continue
            sections.append({'name': sec.attrib['name'],
                             'id': sec_id})
        return sections


neutron_sg = NeutronSecurityGroupDB()
nsxv_firewall = NsxFirewallAPI()


def _log_info(resource, data, attrs=['name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


def list_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST.value)
        return func
    return wrap


def list_mismatches_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST_MISMATCHES.value)
        return func
    return wrap


@list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def neutron_list_security_groups_mappings(resource, event, trigger, **kwargs):
    sg_mappings = neutron_sg.get_security_groups_mappings()
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['name', 'id', 'section-id', 'nsx-securitygroup-id'])
    return bool(sg_mappings)


@list_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def nsx_list_dfw_sections(resource, event, trigger, **kwargs):
    fw_sections = nsxv_firewall.list_fw_sections()
    _log_info(constants.FIREWALL_SECTIONS, fw_sections)
    return bool(fw_sections)


@list_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    nsx_secgroups = nsxv_firewall.list_security_groups()
    _log_info(constants.FIREWALL_NSX_GROUPS, nsx_secgroups)
    return bool(nsx_secgroups)


@list_mismatches_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def list_missing_security_groups(resource, event, trigger, **kwargs):
    nsx_secgroups = nsxv_firewall.list_security_groups()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_nsx_secgroups = []
    for sg_db in sg_mappings:
        for nsx_sg in nsx_secgroups:
            if nsx_sg['id'] == sg_db['nsx-securitygroup-id']:
                break
        else:
            missing_nsx_secgroups.append({'securitygroup-name': sg_db['name'],
                                          'securitygroup-id': sg_db['id'],
                                          'nsx-securitygroup-id':
                                          sg_db['nsx-securitygroup-id']})
    _log_info(constants.FIREWALL_NSX_GROUPS, missing_nsx_secgroups,
              attrs=['securitygroup-name', 'securitygroup-id',
                     'nsx-securitygroup-id'])
    return bool(missing_nsx_secgroups)


@list_mismatches_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def list_missing_firewall_sections(resource, event, trigger, **kwargs):
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_sections = []
    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db['section-id']:
                break
        else:
            missing_sections.append({'securitygroup-name': sg_db['name'],
                                     'securitygroup-id': sg_db['id'],
                                     'section-id': sg_db['section-id']})
    _log_info(constants.FIREWALL_SECTIONS, missing_sections,
              attrs=['securitygroup-name', 'securitygroup-id', 'section-id'])
    return bool(missing_sections)
