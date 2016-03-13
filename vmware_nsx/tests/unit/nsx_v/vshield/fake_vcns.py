# Copyright 2013 VMware, Inc
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

import copy

from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import six
import xml.etree.ElementTree as ET

from vmware_nsx._i18n import _
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions

SECTION_LOCATION_HEADER = '/api/4.0/firewall/globalroot-0/config/%s/%s'


class FakeVcns(object):

    errors = {
        303: exceptions.ResourceRedirect,
        400: exceptions.RequestBad,
        403: exceptions.Forbidden,
        404: exceptions.ResourceNotFound,
        415: exceptions.MediaTypeUnsupport,
        503: exceptions.ServiceUnavailable
    }

    def __init__(self, unique_router_name=True):
        self._jobs = {}
        self._job_idx = 0
        self._edges = {}
        self._edge_idx = 0
        self._lswitches = {}
        self._unique_router_name = unique_router_name
        self._fake_nsx_api = None
        self.fake_firewall_dict = {}
        self.temp_firewall = {
            "firewallRules": {
                "firewallRules": []
            }
        }
        self.fake_ipsecvpn_dict = {}
        self.temp_ipsecvpn = {
            'featureType': "ipsec_4.0",
            'enabled': True,
            'sites': {'sites': []}}
        self._fake_virtualservers_dict = {}
        self._fake_pools_dict = {}
        self._fake_monitors_dict = {}
        self._fake_app_profiles_dict = {}
        self._fake_loadbalancer_config = {}
        self._fake_virtual_wires = {}
        self._virtual_wire_id = 0
        self._fake_portgroups = {}
        self._portgroup_id = 0
        self._securitygroups = {'ids': 0, 'names': set()}
        self._sections = {'section_ids': 0, 'rule_ids': 0, 'names': set()}
        self._dhcp_bindings = {}
        self._spoofguard_policies = []

    def set_fake_nsx_api(self, fake_nsx_api):
        self._fake_nsx_api = fake_nsx_api

    def _validate_edge_name(self, name):
        for edge_id, edge in six.iteritems(self._edges):
            if edge['name'] == name:
                return False
        return True

    def get_edge_jobs(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {
            'status': 200
        }
        response = {"edgeJob": []}
        return (header, response)

    def deploy_edge(self, request, async=True):
        if (self._unique_router_name and
            not self._validate_edge_name(request['name'])):
            header = {
                'status': 400
            }
            msg = ('Edge name should be unique for tenant. Edge %s '
                   'already exists for default tenant.') % request['name']
            response = {
                'details': msg,
                'errorCode': 10085,
                'rootCauseString': None,
                'moduleName': 'vShield Edge',
                'errorData': None
            }
            return (header, jsonutils.dumps(response))

        if async:
            self._job_idx = self._job_idx + 1
            job_id = "jobdata-%d" % self._job_idx
            self._edge_idx = self._edge_idx + 1
            edge_id = "edge-%d" % self._edge_idx
            self._jobs[job_id] = edge_id
            self._edges[edge_id] = {
                'name': request['name'],
                'request': request,
                'nat_rules': None,
                'nat_rule_id': 0,
                'interface_index': 1
            }
            header = {
                'status': 200,
                'location': 'https://host/api/4.0/jobs/%s' % job_id
            }
            response = ''
        else:
            self._edge_idx = self._edge_idx + 1
            edge_id = "edge-%d" % self._edge_idx
            self._edges[edge_id] = {
                'name': request['name'],
                'request': request,
                'nat_rules': None,
                'nat_rule_id': 0,
                'interface_index': 1
            }
            header = {
                'status': 200,
                'location': 'https://host/api/4.0/edges/%s' % edge_id
            }
            response = ''
        return (header, response)

    def update_edge(self, edge_id, request):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        edge = self._edges[edge_id]
        edge['name'] = request['name']
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def get_edge_id(self, job_id):
        if job_id not in self._jobs:
            raise Exception(_("Job %s does not nexist") % job_id)

        header = {
            'status': 200
        }
        response = {
            'edgeId': self._jobs[job_id]
        }
        return (header, response)

    def get_edge_deploy_status(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {
            'status': 200,
        }
        response = {
            'systemStatus': 'good'
        }
        return (header, response)

    def delete_edge(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        del self._edges[edge_id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def add_vdr_internal_interface(self, edge_id, interface):
        interface = interface['interfaces'][0]
        if not self._edges[edge_id].get('interfaces'):
            self._edges[edge_id]['interfaces'] = []
        index = len(self._edges[edge_id]['interfaces'])
        interface['index'] = str(index)
        self._edges[edge_id]['interfaces'].append(interface)
        header = {
            'status': 200
        }
        response = {"interfaces": [{"index": str(index)}]}
        return (header, response)

    def get_edge_interfaces(self, edge_id):
        if not self._edges[edge_id].get('interfaces'):
            self._edges[edge_id]['interfaces'] = []
        header = {
            'status': 200
        }
        response = {"interfaces": self._edges[edge_id].get('interfaces', [])}
        return (header, response)

    def update_vdr_internal_interface(
        self, edge_id, interface_index, interface):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def get_vdr_internal_interface(self, edge_id, interface_index):
        response = {}
        header = {
            'status': 200
        }
        for interface in self._edges[edge_id].get('interfaces', []):
            if int(interface['index']) == int(interface_index):
                response = interface
        return (header, response)

    def delete_vdr_internal_interface(self, edge_id, interface_index):
        for interface in self._edges[edge_id].get('interfaces', []):
            if int(interface['index']) == int(interface_index):
                header = {
                    'status': 200
                }
                break
        header = {'status': 404}
        response = ''
        return (header, response)

    def get_interfaces(self, edge_id):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def update_interface(self, edge_id, vnic):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def delete_interface(self, edge_id, vnic_index):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def query_interface(self, edge_id, vnic_index):
        header = {
            'status': 200
        }
        response = {
            'label': 'vNic_1',
            'name': 'internal1',
            'address_groups': {'address_groups': []},
            'mtu': 1500,
            'type': 'trunk',
            'subInterfaces': {'subInterfaces': []},
            'isConnected': True
        }
        return (header, response)

    def reconfigure_dhcp_service(self, edge_id, request):
        header = {
            'status': 201
        }
        response = ''
        return (header, response)

    def query_dhcp_configuration(self, edge_id):
        header = {
            'status': 200
        }
        response = {
            "featureType": "dhcp_4.0",
            "version": 14,
            "enabled": True,
            "staticBindings": {"staticBindings": [{}]},
            "ipPools": {"ipPools": []}
        }
        return (header, response)

    def create_dhcp_binding(self, edge_id, request):
        if not self._dhcp_bindings.get(edge_id):
            self._dhcp_bindings[edge_id] = {}
            self._dhcp_bindings[edge_id]['idx'] = 0
        binding_idx = self._dhcp_bindings[edge_id]['idx']
        binding_idx_str = "binding-" + str(binding_idx)
        self._dhcp_bindings[edge_id][binding_idx_str] = request
        self._dhcp_bindings[edge_id]['idx'] = binding_idx + 1
        header = {
            'status': 200,
            'location': '/dhcp/config/bindings/%s' % binding_idx_str
        }
        response = ''
        return (header, response)

    def delete_dhcp_binding(self, edge_id, binding_id):
        if binding_id not in self._dhcp_bindings[edge_id]:
            raise Exception(_("binding %s does not exist") % binding_id)
        del self._dhcp_bindings[edge_id][binding_id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def create_bridge(self, edge_id, request):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {
            'status': 204
        }
        response = ''
        return (header, response)

    def delete_bridge(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {
            'status': 204
        }
        response = ''
        return (header, response)

    def get_nat_config(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        edge = self._edges[edge_id]
        rules = edge['nat_rules']
        if rules is None:
            rules = {
                'rules': {
                    'natRulesDtos': []
                },
                'version': 1
            }
        header = {
            'status': 200
        }
        rules['version'] = 1
        return (header, rules)

    def update_nat_config(self, edge_id, nat):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)
        edge = self._edges[edge_id]
        max_rule_id = edge['nat_rule_id']
        rules = copy.deepcopy(nat)
        for rule in rules['rules']['natRulesDtos']:
            rule_id = rule.get('ruleId', 0)
            if rule_id > max_rule_id:
                max_rule_id = rule_id
        for rule in rules['rules']['natRulesDtos']:
            if 'ruleId' not in rule:
                max_rule_id = max_rule_id + 1
                rule['ruleId'] = max_rule_id
        edge['nat_rules'] = rules
        edge['nat_rule_id'] = max_rule_id
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def delete_nat_rule(self, edge_id, rule_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)

        edge = self._edges[edge_id]
        rules = edge['nat_rules']
        rule_to_delete = None
        for rule in rules['rules']['natRulesDtos']:
            if rule_id == rule['ruleId']:
                rule_to_delete = rule
                break
        if rule_to_delete is None:
            raise Exception(_("Rule id %d doest not exist") % rule_id)

        rules['rules']['natRulesDtos'].remove(rule_to_delete)

        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def get_edge_status(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist") % edge_id)

        header = {
            'status': 200
        }
        response = {
            'edgeStatus': 'GREEN'
        }
        return (header, response)

    def get_edge(self, edge_id):
        if edge_id not in self._edges:
            raise Exception(_("Edge %s does not exist!") % edge_id)
        header = {
            'status': 200
        }
        response = {
            'name': 'fake-edge',
            'id': edge_id
        }
        return (header, response)

    def get_edges(self):
        header = {
            'status': 200
        }
        edges = []
        for edge_id in self._edges:
            edges.append({
                'id': edge_id,
                'edgeStatus': 'GREEN'
            })
        response = {
            'edgePage': {
                'data': edges
            }
        }
        return (header, response)

    def update_routes(self, edge_id, routes):
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def create_lswitch(self, lsconfig):
        # The lswitch is created via VCNS API so the fake nsx_api will not
        # see it. Added to fake nsx_api here.
        if self._fake_nsx_api:
            lswitch = self._fake_nsx_api._add_lswitch(
                jsonutils.dumps(lsconfig))
        else:
            lswitch = lsconfig
            lswitch['uuid'] = uuidutils.generate_uuid()
        self._lswitches[lswitch['uuid']] = lswitch
        header = {
            'status': 200
        }
        lswitch['_href'] = '/api/ws.v1/lswitch/%s' % lswitch['uuid']
        return (header, lswitch)

    def delete_lswitch(self, id):
        if id not in self._lswitches:
            raise Exception(_("Lswitch %s does not exist") % id)
        del self._lswitches[id]
        if self._fake_nsx_api:
            # TODO(fank): fix the hack
            del self._fake_nsx_api._fake_lswitch_dict[id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def update_firewall(self, edge_id, fw_req):
        self.fake_firewall_dict[edge_id] = fw_req
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        index = 10
        for rule in rules:
            rule['ruleId'] = index
            index += 10
        header = {'status': 204}
        response = ""
        return self.return_helper(header, response)

    def delete_firewall(self, edge_id):
        header = {'status': 404}
        if edge_id in self.fake_firewall_dict:
            header = {'status': 204}
            del self.fake_firewall_dict[edge_id]
        response = ""
        return self.return_helper(header, response)

    def update_firewall_rule(self, edge_id, vcns_rule_id, fwr_req):
        if edge_id not in self.fake_firewall_dict:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {'status': 404}
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        for rule in rules:
            if rule['ruleId'] == int(vcns_rule_id):
                header['status'] = 204
                rule.update(fwr_req)
                break
        response = ""
        return self.return_helper(header, response)

    def delete_firewall_rule(self, edge_id, vcns_rule_id):
        if edge_id not in self.fake_firewall_dict:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {'status': 404}
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        for index in range(len(rules)):
            if rules[index]['ruleId'] == int(vcns_rule_id):
                header['status'] = 204
                del rules[index]
                break
        response = ""
        return self.return_helper(header, response)

    def add_firewall_rule_above(self, edge_id, ref_vcns_rule_id, fwr_req):
        if edge_id not in self.fake_firewall_dict:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {'status': 404}
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        pre = 0
        for index in range(len(rules)):
            if rules[index]['ruleId'] == int(ref_vcns_rule_id):
                rules.insert(index, fwr_req)
                rules[index]['ruleId'] = (int(ref_vcns_rule_id) + pre) / 2
                header = {
                    'status': 204,
                    'location': "https://host/api/4.0/edges/edge_id/firewall"
                                "/config/rules/%s" % rules[index]['ruleId']}
                break
            pre = int(rules[index]['ruleId'])
        response = ""
        return self.return_helper(header, response)

    def add_firewall_rule(self, edge_id, fwr_req):
        if edge_id not in self.fake_firewall_dict:
            self.fake_firewall_dict[edge_id] = self.temp_firewall
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        rules.append(fwr_req)
        index = len(rules)
        rules[index - 1]['ruleId'] = index * 10
        header = {
            'status': 204,
            'location': "https://host/api/4.0/edges/edge_id/firewall"
                        "/config/rules/%s" % rules[index - 1]['ruleId']}
        response = ""
        return self.return_helper(header, response)

    def get_firewall(self, edge_id):
        if edge_id not in self.fake_firewall_dict:
            self.fake_firewall_dict[edge_id] = self.temp_firewall
        header = {'status': 204}
        response = self.fake_firewall_dict[edge_id]
        return self.return_helper(header, response)

    def get_firewall_rule(self, edge_id, vcns_rule_id):
        if edge_id not in self.fake_firewall_dict:
            raise Exception(_("Edge %s does not exist") % edge_id)
        header = {'status': 404}
        response = ""
        rules = self.fake_firewall_dict[edge_id][
            'firewallRules']['firewallRules']
        for rule in rules:
            if rule['ruleId'] == int(vcns_rule_id):
                header['status'] = 204
                response = rule
                break
        return self.return_helper(header, response)

    def is_name_unique(self, objs_dict, name):
        return name not in [obj_dict['name']
                            for obj_dict in objs_dict.values()]

    def create_vip(self, edge_id, vip_new):
        header = {'status': 403}
        response = ""
        if not self._fake_virtualservers_dict.get(edge_id):
            self._fake_virtualservers_dict[edge_id] = {}
        if not self.is_name_unique(self._fake_virtualservers_dict[edge_id],
                                   vip_new['name']):
            return self.return_helper(header, response)
        vip_vseid = uuidutils.generate_uuid()
        self._fake_virtualservers_dict[edge_id][vip_vseid] = vip_new
        header = {
            'status': 204,
            'location': "https://host/api/4.0/edges/edge_id"
                        "/loadbalancer/config/%s" % vip_vseid}
        return self.return_helper(header, response)

    def get_vip(self, edge_id, vip_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_virtualservers_dict.get(edge_id) or (
            not self._fake_virtualservers_dict[edge_id].get(vip_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        response = self._fake_virtualservers_dict[edge_id][vip_vseid]
        return self.return_helper(header, response)

    def update_vip(self, edge_id, vip_vseid, vip_new):
        header = {'status': 404}
        response = ""
        if not self._fake_virtualservers_dict.get(edge_id) or (
            not self._fake_virtualservers_dict[edge_id].get(vip_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        self._fake_virtualservers_dict[edge_id][vip_vseid].update(
            vip_new)
        return self.return_helper(header, response)

    def delete_vip(self, edge_id, vip_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_virtualservers_dict.get(edge_id) or (
            not self._fake_virtualservers_dict[edge_id].get(vip_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        del self._fake_virtualservers_dict[edge_id][vip_vseid]
        return self.return_helper(header, response)

    def create_pool(self, edge_id, pool_new):
        header = {'status': 403}
        response = ""
        if not self._fake_pools_dict.get(edge_id):
            self._fake_pools_dict[edge_id] = {}
        if not self.is_name_unique(self._fake_pools_dict[edge_id],
                                   pool_new['name']):
            return self.return_helper(header, response)
        pool_vseid = uuidutils.generate_uuid()
        self._fake_pools_dict[edge_id][pool_vseid] = pool_new
        header = {
            'status': 204,
            'location': "https://host/api/4.0/edges/edge_id"
                        "/loadbalancer/config/%s" % pool_vseid}
        return self.return_helper(header, response)

    def get_pool(self, edge_id, pool_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_pools_dict.get(edge_id) or (
            not self._fake_pools_dict[edge_id].get(pool_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        response = self._fake_pools_dict[edge_id][pool_vseid]
        return self.return_helper(header, response)

    def update_pool(self, edge_id, pool_vseid, pool_new):
        header = {'status': 404}
        response = ""
        if not self._fake_pools_dict.get(edge_id) or (
            not self._fake_pools_dict[edge_id].get(pool_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        self._fake_pools_dict[edge_id][pool_vseid].update(
            pool_new)
        return self.return_helper(header, response)

    def delete_pool(self, edge_id, pool_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_pools_dict.get(edge_id) or (
            not self._fake_pools_dict[edge_id].get(pool_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        del self._fake_pools_dict[edge_id][pool_vseid]
        return self.return_helper(header, response)

    def create_health_monitor(self, edge_id, monitor_new):
        if not self._fake_monitors_dict.get(edge_id):
            self._fake_monitors_dict[edge_id] = {}
        monitor_vseid = uuidutils.generate_uuid()
        self._fake_monitors_dict[edge_id][monitor_vseid] = monitor_new
        header = {
            'status': 204,
            'location': "https://host/api/4.0/edges/edge_id"
                        "/loadbalancer/config/%s" % monitor_vseid}
        response = ""
        return self.return_helper(header, response)

    def get_health_monitor(self, edge_id, monitor_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_monitors_dict.get(edge_id) or (
            not self._fake_monitors_dict[edge_id].get(monitor_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        response = self._fake_monitors_dict[edge_id][monitor_vseid]
        return self.return_helper(header, response)

    def update_health_monitor(self, edge_id, monitor_vseid, monitor_new):
        header = {'status': 404}
        response = ""
        if not self._fake_monitors_dict.get(edge_id) or (
            not self._fake_monitors_dict[edge_id].get(monitor_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        self._fake_monitors_dict[edge_id][monitor_vseid].update(
            monitor_new)
        return self.return_helper(header, response)

    def delete_health_monitor(self, edge_id, monitor_vseid):
        header = {'status': 404}
        response = ""
        if not self._fake_monitors_dict.get(edge_id) or (
            not self._fake_monitors_dict[edge_id].get(monitor_vseid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        del self._fake_monitors_dict[edge_id][monitor_vseid]
        return self.return_helper(header, response)

    def create_app_profile(self, edge_id, app_profile):
        if not self._fake_app_profiles_dict.get(edge_id):
            self._fake_app_profiles_dict[edge_id] = {}
        app_profileid = uuidutils.generate_uuid()
        self._fake_app_profiles_dict[edge_id][app_profileid] = app_profile
        header = {
            'status': 204,
            'location': "https://host/api/4.0/edges/edge_id"
                        "/loadbalancer/config/%s" % app_profileid}
        response = ""
        return self.return_helper(header, response)

    def update_app_profile(self, edge_id, app_profileid, app_profile):
        header = {'status': 404}
        response = ""
        if not self._fake_app_profiles_dict.get(edge_id) or (
            not self._fake_app_profiles_dict[edge_id].get(app_profileid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        self._fake_app_profiles_dict[edge_id][app_profileid].update(
            app_profile)
        return self.return_helper(header, response)

    def delete_app_profile(self, edge_id, app_profileid):
        header = {'status': 404}
        response = ""
        if not self._fake_app_profiles_dict.get(edge_id) or (
            not self._fake_app_profiles_dict[edge_id].get(app_profileid)):
            return self.return_helper(header, response)
        header = {'status': 204}
        del self._fake_app_profiles_dict[edge_id][app_profileid]
        return self.return_helper(header, response)

    def get_loadbalancer_config(self, edge_id):
        header = {'status': 204}
        response = {'config': False}
        if self._fake_loadbalancer_config[edge_id]:
            response['config'] = self._fake_loadbalancer_config[edge_id]
        return self.return_helper(header, response)

    def update_ipsec_config(self, edge_id, ipsec_config):
        self.fake_ipsecvpn_dict[edge_id] = ipsec_config
        header = {'status': 204}
        response = ""
        return self.return_helper(header, response)

    def delete_ipsec_config(self, edge_id):
        header = {'status': 404}
        if edge_id in self.fake_ipsecvpn_dict:
            header = {'status': 204}
            del self.fake_ipsecvpn_dict[edge_id]
        response = ""
        return self.return_helper(header, response)

    def get_ipsec_config(self, edge_id):
        if edge_id not in self.fake_ipsecvpn_dict:
            self.fake_ipsecvpn_dict[edge_id] = self.temp_ipsecvpn
        header = {'status': 204}
        response = self.fake_ipsecvpn_dict[edge_id]
        return self.return_helper(header, response)

    def enable_service_loadbalancer(self, edge_id, config):
        header = {'status': 204}
        response = ""
        self._fake_loadbalancer_config[edge_id] = True
        return self.return_helper(header, response)

    def create_virtual_wire(self, vdn_scope_id, request):
        self._virtual_wire_id += 1
        header = {'status': 200}
        virtual_wire = 'virtualwire-%s' % self._virtual_wire_id
        data = {'name': request['virtualWireCreateSpec']['name'],
                'objectId': virtual_wire}
        self._fake_virtual_wires.update({virtual_wire: data})
        return (header, virtual_wire)

    def delete_virtual_wire(self, virtualwire_id):
        del self._fake_virtual_wires[virtualwire_id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def create_port_group(self, dvs_id, request):
        self._portgroup_id += 1
        header = {'status': 200}
        portgroup = 'dvportgroup-%s' % self._portgroup_id
        data = {'name': request['networkSpec']['networkName'],
                'objectId': portgroup}
        self._fake_portgroups.update({portgroup: data})
        return (header, portgroup)

    def delete_port_group(self, dvs_id, portgroup_id):
        del self._fake_portgroups[portgroup_id]
        header = {
            'status': 200
        }
        response = ''
        return (header, response)

    def return_helper(self, header, response):
        status = int(header['status'])
        if 200 <= status <= 300:
            return (header, response)
        if status in self.errors:
            cls = self.errors[status]
        else:
            cls = exceptions.VcnsApiException
        raise cls(
            status=status, header=header, uri='fake_url', response=response)

    def _get_bad_req_response(self, details, error_code, module_name):
        bad_req_response_format = """
            <error>
            <details>%(details)s</details>
            <errorCode>%(error_code)s</errorCode>
            <moduleName>%(module_name)s</moduleName>
            </error>
            """
        return bad_req_response_format % {
            'details': details,
            'error_code': error_code,
            'module_name': module_name,
        }

    def _get_section_location(self, type, section_id):
        return SECTION_LOCATION_HEADER % (type, section_id)

    def _get_section_id_from_uri(self, section_uri):
        return section_uri.split('/')[-1]

    def _section_not_found(self, section_id):
        msg = "Invalid section id found : %s" % section_id
        response = self._get_bad_req_response(msg, 100089, 'vShield App')
        headers = {'status': 400}
        return (headers, response)

    def _unknown_error(self):
        msg = "Unknown Error Occurred.Please look into tech support logs."
        response = self._get_bad_req_response(msg, 100046, 'vShield App')
        headers = {'status': 400}
        return (headers, response)

    def create_security_group(self, request):
        sg = request['securitygroup']
        if sg['name'] in self._securitygroups['names']:
            status = 400
            msg = ("Another object with same name : %s already exists in "
                   "the current scope : globalroot-0." % sg['name'])
            response = self._get_bad_req_response(msg, 210, 'core-services')
        else:
            sg_id = str(self._securitygroups['ids'])
            self._securitygroups['ids'] += 1
            sg['members'] = set()
            self._securitygroups[sg_id] = sg
            self._securitygroups['names'].add(sg['name'])
            status, response = 201, sg_id
        return ({'status': status}, response)

    def update_security_group(self, sg_id, sg_name, description):
        sg = self._securitygroups[sg_id]
        self._securitygroups['names'].remove(sg['name'])
        sg['name'] = sg_name
        sg['description'] = description
        self._securitygroups['names'].add(sg_name)
        return {'status': 200}, ''

    def delete_security_group(self, securitygroup_id):
        try:
            del self._securitygroups[securitygroup_id]
        except KeyError:
            status = 404
            msg = ("The requested object : %s could "
                   "not be found. Object identifiers are case sensitive."
                   % securitygroup_id)
            response = self._get_bad_req_response(msg, 210, 'core-services')
        else:
            status, response = 200, ''
        return ({'status': status}, response)

    def get_security_group_id(self, sg_name):
        for k, v in self._securitygroups.items():
            if k not in ('ids', 'names') and v['name'] == sg_name:
                return k

    def create_section(self, type, request, insert_before=None):
        section = ET.fromstring(request)
        section_name = section.attrib.get('name')
        if section_name in self._sections['names']:
            msg = "Section with name %s already exists." % section_name
            response = self._get_bad_req_response(msg, 100092, 'vShield App')
            headers = {'status': 400}
        else:
            section_id = str(self._sections['section_ids'])
            section.attrib['id'] = 'section-%s' % section_id
            _section = self._sections[section_id] = {'name': section_name,
                                                     'etag': 'Etag-0',
                                                     'rules': {}}
            self._sections['names'].add(section_name)
            for rule in section.findall('rule'):
                rule_id = str(self._sections['rule_ids'])
                rule.attrib['id'] = rule_id
                _section['rules'][rule_id] = ET.tostring(rule)
                self._sections['rule_ids'] += 1
            response = ET.tostring(section)
            headers = {
                'status': 201,
                'location': self._get_section_location(type, section_id),
                'etag': _section['etag']
            }
            self._sections['section_ids'] += 1
        return (headers, response)

    def update_section(self, section_uri, request, h):
        section = ET.fromstring(request)
        section_id = section.attrib.get('id')
        section_name = section.attrib.get('name')
        if section_id not in self._sections:
            return self._section_not_found(section_id)
        _section = self._sections[section_id]
        if (_section['name'] != section_name and
            section_name in self._sections['names']):
                # Theres a section with this name already
                headers, response = self._unknown_error()
        else:
            # Different Etag every successful update
            _section['etag'] = ('Etag-1' if _section['etag'] == 'Etag-0'
                                else 'Etag-0')
            self._sections['names'].remove(_section['name'])
            _section['name'] = section_name
            self._sections['names'].add(section_name)
            for rule in section.findall('rule'):
                if not rule.attrib.get('id'):
                    rule.attrib['id'] = str(self._sections['rule_ids'])
                    self._sections['rule_ids'] += 1
                rule_id = rule.attrib.get('id')
                _section['rules'][rule_id] = ET.tostring(rule)
            _, response = self._get_section(section_id)
            headers = {
                'status': 200,
                'location': self._get_section_location(type, section_id),
                'etag': _section['etag']
            }
        return (headers, response)

    def delete_section(self, section_uri):
        section_id = self._get_section_id_from_uri(section_uri)
        if section_id not in self._sections:
            headers, response = self._unknown_error()
        else:
            section_name = self._sections[section_id]['name']
            del self._sections[section_id]
            self._sections['names'].remove(section_name)
            response = ''
            headers = {'status': 204}
        return (headers, response)

    def get_section(self, section_uri):
        section_id = self._get_section_id_from_uri(section_uri)
        if section_id not in self._sections:
            headers, response = self._section_not_found(section_id)
        else:
            return self._get_section(section_id)

    def _get_section(self, section_id):
        section_rules = (''.join(self._sections[section_id]['rules'].values()))
        response = ('<section id="%s">%s</section>'
                    % (section_id, section_rules))
        headers = {'status': 200,
                   'etag': self._sections[section_id]['etag']}
        return (headers, response)

    def get_section_id(self, section_name):
        self._sections = {'section_ids': 0, 'rule_ids': 0, 'names': set()}
        for k, v in self._sections.items():
            if (k not in ('section_ids', 'rule_ids', 'names')
                and v['name'] == section_name):
                return k

    def remove_rule_from_section(self, section_uri, rule_id):
        section_id = self._get_section_id_from_uri(section_uri)
        if section_id not in self._sections:
            headers, response = self._section_not_found(section_id)
        else:
            section = self._sections[section_id]
            if rule_id in section['rules']:
                del section['rules'][rule_id]
                response = ''
                headers = {'status': 204}
            else:
                headers, response = self._unknown_error()
        return (headers, response)

    def add_member_to_security_group(self, security_group_id, member_id):
        if security_group_id not in self._securitygroups:
            msg = ("The requested object : %s could not be found."
                   "Object identifiers are case "
                   "sensitive.") % security_group_id
            response = self._get_bad_req_response(msg, 202, 'core-services')
            headers = {'status': 404}
        else:
            self._securitygroups[security_group_id]['members'].add(member_id)
            response = ''
            headers = {'status': 200}
        return (headers, response)

    def remove_member_from_security_group(self, security_group_id, member_id):
        if security_group_id not in self._securitygroups:
            msg = ("The requested object : %s could not be found."
                   "Object identifiers are "
                   "case sensitive.") % security_group_id
            response = self._get_bad_req_response(msg, 202, 'core-services')
            headers = {'status': 404}
        else:
            self._securitygroups[security_group_id]['members'].remove(
                member_id)
            response = ''
            headers = {'status': 200}
        return (headers, response)

    def create_spoofguard_policy(self, enforcement_point, name, enable):
        policy = {'name': name,
                  'enforcement_point': enforcement_point,
                  'operationMode': 'MANUAL' if enable else 'DISABLE'}
        policy_id = len(self._spoofguard_policies)
        self._spoofguard_policies.append(policy)
        return None, policy_id

    def update_spoofguard_policy(self, policy_id,
                                 enforcement_point, name, enable):
        policy = {'name': name,
                  'enforcement_point': enforcement_point,
                  'operationMode': 'MANUAL' if enable else 'DISABLE'}
        self._spoofguard_policies[int(policy_id)] = policy
        return None, ''

    def delete_spoofguard_policy(self, policy_id):
        self._spoofguard_policies[int(policy_id)] = {}

    def get_spoofguard_policy(self, policy_id):
        return None, self._spoofguard_policies[int(policy_id)]

    def get_spoofguard_policies(self):
        return None, self._spoofguard_policies

    def approve_assigned_addresses(self, policy_id,
                                   vnic_id, mac_addr, addresses):
        pass

    def publish_assigned_addresses(self, policy_id, vnic_id):
        pass

    def configure_reservations(self):
        pass

    def inactivate_vnic_assigned_addresses(self, policy_id, vnic_id):
        pass

    def reset_all(self):
        self._jobs.clear()
        self._edges.clear()
        self._lswitches.clear()
        self.fake_firewall_dict = {}
        self._fake_virtualservers_dict = {}
        self._fake_pools_dict = {}
        self._fake_monitors_dict = {}
        self._fake_app_profiles_dict = {}
        self._fake_loadbalancer_config = {}
        self._fake_virtual_wires = {}
        self._virtual_wire_id = 0
        self._fake_portgroups = {}
        self._portgroup_id = 0
        self._securitygroups = {'ids': 0, 'names': set()}
        self._sections = {'section_ids': 0, 'rule_ids': 0, 'names': set()}
        self._dhcp_bindings = {}

    def validate_datacenter_moid(self, object_id):
        return True

    def validate_network(self, object_id):
        return True

    def validate_network_name(self, object_id, name):
        return True

    def validate_vdn_scope(self, object_id):
        return True

    def validate_dvs(self, object_id):
        return True

    def edges_lock_operation(self):
        pass

    def validate_inventory(self, moref):
        return True

    def get_version(self):
        return '6.2.0'

    def get_tuning_configration(self):
        return {
            'lockUpdatesOnEdge': True,
            'edgeVMHealthCheckIntervalInMin': 0,
            'aggregatePublishing': False,
            'publishingTimeoutInMs': 1200000,
            'healthCheckCommandTimeoutInMs': 120000,
            'maxParallelVixCallsForHealthCheck': 25}

    def configure_aggregate_publishing(self):
        pass

    def enable_ha(self, edge_id, request_config):
        header = {
            'status': 201
        }
        response = ''
        return (header, response)

    def change_edge_appliance_size(self, edge_id, size):
        header = {
            'status': 204
        }
        response = {}
        return (header, response)
