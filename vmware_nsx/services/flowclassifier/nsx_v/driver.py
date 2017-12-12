# Copyright 2016 VMware, Inc.
#
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

import xml.etree.ElementTree as et

from networking_sfc.extensions import flowclassifier
from networking_sfc.services.flowclassifier.common import exceptions as exc
from networking_sfc.services.flowclassifier.drivers import base as fc_driver
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.plugins.nsx_v.vshield import vcns as nsxv_api
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.flowclassifier.nsx_v import utils as fc_utils

LOG = logging.getLogger(__name__)

REDIRECT_FW_SECTION_NAME = 'OS Flow Classifier Rules'


class NsxvFlowClassifierDriver(fc_driver.FlowClassifierDriverBase):
    """FlowClassifier Driver For NSX-V."""

    _redirect_section_id = None

    def initialize(self):
        self._nsxv = vcns_driver.VcnsDriver(None)
        self.init_profile_id()
        self.init_security_group()
        self.init_security_group_in_profile()

        # register an event to the end of the init to handle the first upgrade
        if self._is_new_security_group:
            registry.subscribe(self.init_complete,
                               resources.PROCESS,
                               events.BEFORE_SPAWN)

    def init_profile_id(self):
        """Init the service insertion profile ID

        Initialize the profile id that should be assigned to the redirect
        rules from the nsx configuration and verify that it exists on backend.
        """
        if not cfg.CONF.nsxv.service_insertion_profile_id:
            raise cfg.RequiredOptError("service_insertion_profile_id",
                                       group=cfg.OptGroup('nsxv'))
        self._profile_id = cfg.CONF.nsxv.service_insertion_profile_id

        # Verify that this moref exists
        if not self._nsxv.vcns.validate_inventory(self._profile_id):
            error = (_("Configured service profile ID: %s not found") %
                     self._profile_id)
            raise nsx_exc.NsxPluginException(err_msg=error)

    def init_security_group(self):
        """Init the service insertion security group

        Look for the service insertion security group in the backend.
        If it was not found - create it
        This security group will contain all the VMs vnics that should
        be inspected by the redirect rules
        """
        # check if this group exist, and create it if not.
        sg_name = fc_utils.SERVICE_INSERTION_SG_NAME
        sg_id = self._nsxv.vcns.get_security_group_id(sg_name)
        self._is_new_security_group = False
        if not sg_id:
            description = ("OpenStack Service Insertion Security Group, "
                           "managed by Neutron nsx-v plugin.")
            sg = {"securitygroup": {"name": sg_name,
                                    "description": description}}
            h, sg_id = (
                self._nsxv.vcns.create_security_group(sg))
            self._is_new_security_group = True

        self._security_group_id = sg_id

    def init_security_group_in_profile(self):
        """Attach the security group to the service profile
        """
        data = self._nsxv.vcns.get_service_insertion_profile(self._profile_id)
        if data and len(data) > 1:
            profile = et.fromstring(data[1])
            profile_binding = profile.find('serviceProfileBinding')
            sec_groups = profile_binding.find('securityGroups')
            for sec in sec_groups.iter('string'):
                if sec.text == self._security_group_id:
                    # Already there
                    return
            # add the security group to the binding
            et.SubElement(sec_groups, 'string').text = self._security_group_id
            self._nsxv.vcns.update_service_insertion_profile_binding(
                self._profile_id,
                et.tostring(profile_binding, encoding="us-ascii"))

    def init_complete(self, resource, event, trigger, payload=None):
        if self._is_new_security_group:
            # add existing VMs to the new security group
            # This code must run after init is done
            core_plugin = directory.get_plugin()
            core_plugin.add_vms_to_service_insertion(
                self._security_group_id)

            # Add the first flow classifier entry
            if cfg.CONF.nsxv.service_insertion_redirect_all:
                self.add_any_any_redirect_rule()

    def add_any_any_redirect_rule(self):
        """Add an any->any flow classifier entry

        Add 1 flow classifier entry that will redirect all the traffic to the
        security partner
        The user will be able to delete/change it later
        """
        context = n_context.get_admin_context()
        fc_plugin = directory.get_plugin(flowclassifier.FLOW_CLASSIFIER_EXT)
        # first check that there is no other flow classifier entry defined:
        fcs = fc_plugin.get_flow_classifiers(context)
        if len(fcs) > 0:
            return

        # Create any->any rule
        fc = {'name': 'redirect_all',
              'description': 'Redirect all traffic',
              'tenant_id': nsxv_constants.INTERNAL_TENANT_ID,
              'l7_parameters': {},
              'ethertype': 'IPv4',
              'protocol': None,
              'source_port_range_min': None,
              'source_port_range_max': None,
              'destination_port_range_min': None,
              'destination_port_range_max': None,
              'source_ip_prefix': None,
              'destination_ip_prefix': None,
              'logical_source_port': None,
              'logical_destination_port': None
              }
        fc_plugin.create_flow_classifier(context, {'flow_classifier': fc})

    def get_redirect_fw_section_id(self):
        if not self._redirect_section_id:
            # try to find it
            self._redirect_section_id = self._nsxv.vcns.get_section_id(
                REDIRECT_FW_SECTION_NAME)
            if not self._redirect_section_id:
                # create it for the first time
                section = et.Element('section')
                section.attrib['name'] = REDIRECT_FW_SECTION_NAME
                self._nsxv.vcns.create_redirect_section(et.tostring(section))
                self._redirect_section_id = self._nsxv.vcns.get_section_id(
                    REDIRECT_FW_SECTION_NAME)

        return self._redirect_section_id

    def get_redirect_fw_section_uri(self):
        return '%s/%s/%s' % (nsxv_api.FIREWALL_PREFIX,
                             nsxv_api.FIREWALL_REDIRECT_SEC_TYPE,
                             self.get_redirect_fw_section_id())

    def get_redirect_fw_section_from_backend(self):
        section_uri = self.get_redirect_fw_section_uri()
        section_resp = self._nsxv.vcns.get_section(section_uri)
        if section_resp and len(section_resp) > 1:
            xml_section = section_resp[1]
            return et.fromstring(xml_section)

    def update_redirect_section_in_backed(self, section):
        section_uri = self.get_redirect_fw_section_uri()
        self._nsxv.vcns.update_section(
            section_uri,
            et.tostring(section, encoding="us-ascii"),
            None)

    def _rule_ip_type(self, flow_classifier):
        if flow_classifier.get('ethertype') == 'IPv6':
            return 'Ipv6Address'
        return 'Ipv4Address'

    def _rule_ports(self, type, flow_classifier):
        min_port = flow_classifier.get(type + '_port_range_min')
        max_port = flow_classifier.get(type + '_port_range_max')
        return self._ports_list(min_port, max_port)

    def _ports_list(self, min_port, max_port):
        """Return a string representing the port/range"""
        if min_port == max_port:
            return str(min_port)
        return "%s-%s" % (min_port, max_port)

    def _rule_name(self, flow_classifier):
        # The name of the rule will include the name & id of the classifier
        # so we can later find it in order to update/delete it.
        # Both the flow classifier DB & the backend has max name length of 255
        # so we may have to trim the name a bit
        return (flow_classifier.get('name')[:200] + '-' +
                flow_classifier.get('id'))

    def _is_the_same_rule(self, rule, flow_classifier_id):
        return rule.find('name').text.endswith(flow_classifier_id)

    def init_redirect_fw_rule(self, redirect_rule, flow_classifier):
        et.SubElement(redirect_rule, 'name').text = self._rule_name(
            flow_classifier)
        et.SubElement(redirect_rule, 'action').text = 'redirect'
        et.SubElement(redirect_rule, 'direction').text = 'inout'
        si_profile = et.SubElement(redirect_rule, 'siProfile')
        et.SubElement(si_profile, 'objectId').text = self._profile_id

        et.SubElement(redirect_rule, 'packetType').text = flow_classifier.get(
            'ethertype').lower()

        # init the source & destination
        if flow_classifier.get('source_ip_prefix'):
            sources = et.SubElement(redirect_rule, 'sources')
            sources.attrib['excluded'] = 'false'
            source = et.SubElement(sources, 'source')
            et.SubElement(source, 'type').text = self._rule_ip_type(
                flow_classifier)
            et.SubElement(source, 'value').text = flow_classifier.get(
                'source_ip_prefix')

        if flow_classifier.get('destination_ip_prefix'):
            destinations = et.SubElement(redirect_rule, 'destinations')
            destinations.attrib['excluded'] = 'false'
            destination = et.SubElement(destinations, 'destination')
            et.SubElement(destination, 'type').text = self._rule_ip_type(
                flow_classifier)
            et.SubElement(destination, 'value').text = flow_classifier.get(
                'destination_ip_prefix')

        # init the service
        if (flow_classifier.get('destination_port_range_min') or
            flow_classifier.get('source_port_range_min')):
            services = et.SubElement(redirect_rule, 'services')
            service = et.SubElement(services, 'service')
            et.SubElement(service, 'isValid').text = 'true'
            if flow_classifier.get('source_port_range_min'):
                source_port = et.SubElement(service, 'sourcePort')
                source_port.text = self._rule_ports('source',
                                                    flow_classifier)

            if flow_classifier.get('destination_port_range_min'):
                dest_port = et.SubElement(service, 'destinationPort')
                dest_port.text = self._rule_ports('destination',
                                                  flow_classifier)

            prot = et.SubElement(service, 'protocolName')
            prot.text = flow_classifier.get('protocol').upper()

        # Add the classifier description
        if flow_classifier.get('description'):
            notes = et.SubElement(redirect_rule, 'notes')
            notes.text = flow_classifier.get('description')

    def _loc_fw_section(self):
        return locking.LockManager.get_lock('redirect-fw-section')

    @log_helpers.log_method_call
    def create_flow_classifier(self, context):
        """Create a redirect rule at the backend
        """
        flow_classifier = context.current
        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            new_rule = et.SubElement(section, 'rule')
            self.init_redirect_fw_rule(new_rule, flow_classifier)
            self.update_redirect_section_in_backed(section)

    @log_helpers.log_method_call
    def update_flow_classifier(self, context):
        """Update the backend redirect rule
        """
        flow_classifier = context.current

        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            redirect_rule = None
            for rule in section.iter('rule'):
                if self._is_the_same_rule(rule, flow_classifier['id']):
                    redirect_rule = rule
                    break

            if redirect_rule is None:
                msg = _("Failed to find redirect rule %s "
                        "on backed") % flow_classifier['id']
                raise exc.FlowClassifierException(message=msg)
            else:
                # The flowclassifier plugin currently supports updating only
                # name or description
                name = redirect_rule.find('name')
                name.text = self._rule_name(flow_classifier)
                notes = redirect_rule.find('notes')
                notes.text = flow_classifier.get('description') or ''
                self.update_redirect_section_in_backed(section)

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context):
        """Delete the backend redirect rule
        """
        flow_classifier_id = context.current['id']
        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            redirect_rule = None
            for rule in section.iter('rule'):
                if self._is_the_same_rule(rule, flow_classifier_id):
                    redirect_rule = rule
                    section.remove(redirect_rule)
                    break

            if redirect_rule is None:
                LOG.error("Failed to delete redirect rule %s: "
                          "Could not find rule on backed",
                          flow_classifier_id)
                # should not fail the deletion
            else:
                self.update_redirect_section_in_backed(section)

    @log_helpers.log_method_call
    def create_flow_classifier_precommit(self, context):
        """Validate the flow classifier data before committing the transaction

        The NSX-v redirect rules does not support:
        - logical ports
        - l7 parameters
        - source ports range / destination port range with more than 15 ports
        """
        flow_classifier = context.current

        # Logical source port
        logical_source_port = flow_classifier['logical_source_port']
        if logical_source_port is not None:
            msg = _('The NSXv driver does not support setting '
                    'logical source port in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)

        # Logical destination port
        logical_destination_port = flow_classifier['logical_destination_port']
        if logical_destination_port is not None:
            msg = _('The NSXv driver does not support setting '
                    'logical destination port in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)

        # L7 parameters
        l7_params = flow_classifier['l7_parameters']
        if l7_params is not None and len(l7_params.keys()) > 0:
            msg = _('The NSXv driver does not support setting '
                    'L7 parameters in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)
