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

from neutron import context
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.db import securitygroups_db

from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_models
from vmware_nsx.db import nsxv_models
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils


LOG = logging.getLogger(__name__)


class NeutronSecurityGroupDB(utils.NeutronDbClient,
                             securitygroups_db.SecurityGroupDbMixin):
    def __init__(self):
        super(NeutronSecurityGroupDB, self)
        # FIXME(roeyc): context is already defined in NeutrondDbClient
        self.context = context.get_admin_context()

    def get_security_groups_mappings(self):
        q = self.context.session.query(
            sg_models.SecurityGroup.name,
            sg_models.SecurityGroup.id,
            nsxv_models.NsxvSecurityGroupSectionMapping.ip_section_id,
            nsx_models.NeutronNsxSecurityGroupMapping.nsx_id).join(
                nsxv_models.NsxvSecurityGroupSectionMapping,
                nsx_models.NeutronNsxSecurityGroupMapping).all()
        sg_mappings = [{'name': mapp.name,
                        'id': mapp.id,
                        'section-uri': mapp.ip_section_id,
                        'nsx-securitygroup-id': mapp.nsx_id}
                       for mapp in q]
        return sg_mappings

    def get_security_group(self, sg_id):
        return super(NeutronSecurityGroupDB, self).get_security_group(
            self.context, sg_id)

    def get_security_groups(self):
        return super(NeutronSecurityGroupDB,
                     self).get_security_groups(self.context)

    def delete_security_group_section_mapping(self, sg_id):
        fw_mapping = self.context.session.query(
            nsxv_models.NsxvSecurityGroupSectionMapping).filter_by(
                neutron_id=sg_id).one_or_none()
        if fw_mapping:
            with self.context.session.begin(subtransactions=True):
                self.context.session.delete(fw_mapping)

    def delete_security_group_backend_mapping(self, sg_id):
        sg_mapping = self.context.session.query(
            nsx_models.NeutronNsxSecurityGroupMapping).filter_by(
                neutron_id=sg_id).one_or_none()
        if sg_mapping:
            with self.context.session.begin(subtransactions=True):
                self.context.session.delete(sg_mapping)

    def get_vnics_in_security_group(self, security_group_id):
        vnics = []
        query = self.context.session.query(
            models_v2.Port.id, models_v2.Port.device_id
        ).join(sg_models.SecurityGroupPortBinding).filter_by(
            security_group_id=security_group_id).all()
        for p in query:
            vnic_index = plugin._get_port_vnic_index(self.context, p.id)
            vnic_id = plugin._get_port_vnic_id(vnic_index, p.device_id)
            vnics.append(vnic_id)
        return vnics


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
plugin = utils.NsxVPluginWrapper()


def _log_info(resource, data, attrs=['name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


@admin_utils.list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def neutron_list_security_groups_mappings(resource, event, trigger, **kwargs):
    sg_mappings = neutron_sg.get_security_groups_mappings()
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['name', 'id', 'section-uri', 'nsx-securitygroup-id'])
    return bool(sg_mappings)


@admin_utils.list_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def nsx_list_dfw_sections(resource, event, trigger, **kwargs):
    fw_sections = nsxv_firewall.list_fw_sections()
    _log_info(constants.FIREWALL_SECTIONS, fw_sections)
    return bool(fw_sections)


@admin_utils.list_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    nsx_secgroups = nsxv_firewall.list_security_groups()
    _log_info(constants.FIREWALL_NSX_GROUPS, nsx_secgroups)
    return bool(nsx_secgroups)


def _find_missing_security_groups():
    nsx_secgroups = nsxv_firewall.list_security_groups()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_secgroups = {}
    for sg_db in sg_mappings:
        for nsx_sg in nsx_secgroups:
            if nsx_sg['id'] == sg_db['nsx-securitygroup-id']:
                break
        else:
            missing_secgroups[sg_db['id']] = sg_db
    return missing_secgroups


@admin_utils.list_mismatches_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def list_missing_security_groups(resource, event, trigger, **kwargs):
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    missing_securitgroups_info = [
        {'securitygroup-name': sg['name'],
         'securitygroup-id': sg['id'],
         'nsx-securitygroup-id':
         sg['nsx-securitygroup-id']}
        for sg in sgs_with_missing_nsx_group.values()]
    _log_info(constants.FIREWALL_NSX_GROUPS, missing_securitgroups_info,
              attrs=['securitygroup-name', 'securitygroup-id',
                     'nsx-securitygroup-id'])
    return bool(missing_securitgroups_info)


def _find_missing_sections():
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_sections = {}
    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db.get('section-uri', '').split('/')[-1]:
                break
        else:
            missing_sections[sg_db['id']] = sg_db
    return missing_sections


@admin_utils.list_mismatches_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def list_missing_firewall_sections(resource, event, trigger, **kwargs):
    sgs_with_missing_section = _find_missing_sections()
    missing_sections_info = [{'securitygroup-name': sg['name'],
                              'securitygroup-id': sg['id'],
                              'section-id': sg['section-uri']}
                             for sg in sgs_with_missing_section.values()]
    _log_info(constants.FIREWALL_SECTIONS, missing_sections_info,
              attrs=['securitygroup-name', 'securitygroup-id', 'section-uri'])
    return bool(missing_sections_info)


@admin_utils.fix_mismatches_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def fix_security_groups(resource, event, trigger, **kwargs):
    context_ = context.get_admin_context()
    sgs_with_missing_section = _find_missing_sections()
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    plugin = utils.NsxVPluginWrapper()
    # If only the fw section is missing then create it.
    for sg_id in (set(sgs_with_missing_section.keys()) -
                  set(sgs_with_missing_nsx_group.keys())):
        neutron_sg.delete_security_group_section_mapping(sg_id)
        secgroup = plugin.get_security_group(context_, sg_id)
        plugin._create_fw_section_for_security_group(
            context_, secgroup,
            sgs_with_missing_section[sg_id]['nsx-securitygroup-id'])

    # If nsx security-group is missing then create both nsx security-group and
    # a new fw section (remove old one).
    for sg_id, sg in sgs_with_missing_nsx_group.items():
        secgroup = plugin.get_security_group(context_, sg_id)
        if sg_id not in sgs_with_missing_section:
            plugin._delete_section(sg['section-uri'])
        neutron_sg.delete_security_group_section_mapping(sg_id)
        neutron_sg.delete_security_group_backend_mapping(sg_id)
        plugin._process_security_group_create_backend_resources(context_,
                                                                secgroup)
        nsx_id = nsx_db.get_nsx_security_group_id(context_.session, sg_id)
        for vnic_id in neutron_sg.get_vnics_in_security_group(sg_id):
            plugin._add_member_to_security_group(nsx_id, vnic_id)
