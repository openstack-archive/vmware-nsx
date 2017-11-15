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

import time
import xml.etree.ElementTree as et

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import strutils
import six

from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils
from vmware_nsx.plugins.nsx_v.vshield.common import constants
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield.common import VcnsApiClient

LOG = logging.getLogger(__name__)

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
URI_PREFIX = "/api/4.0/edges"

#FwaaS constants
FIREWALL_SERVICE = "firewall/config"
FIREWALL_RULE_RESOURCE = "rules"

#NSXv Constants
FIREWALL_PREFIX = '/api/4.0/firewall/globalroot-0/config'
FIREWALL_REDIRECT_SEC_TYPE = 'layer3redirectsections'
SECURITYGROUP_PREFIX = '/api/2.0/services/securitygroup'
VDN_PREFIX = '/api/2.0/vdn'
SERVICES_PREFIX = '/api/2.0/services'
SPOOFGUARD_PREFIX = '/api/4.0/services/spoofguard'
TRUSTSTORE_PREFIX = '%s/%s' % (SERVICES_PREFIX, 'truststore')
EXCLUDELIST_PREFIX = '/api/2.1/app/excludelist'
SERVICE_INSERTION_PROFILE_PREFIX = '/api/2.0/si/serviceprofile'
SECURITY_POLICY_PREFIX = '/api/2.0/services/policy/securitypolicy'
APPLICATION_PREFIX = '%s/%s' % (SERVICES_PREFIX, 'application')

#LbaaS Constants
LOADBALANCER_SERVICE = "loadbalancer/config"
LOADBALANCER_STATS = "loadbalancer/statistics"
VIP_RESOURCE = "virtualservers"
POOL_RESOURCE = "pools"
MONITOR_RESOURCE = "monitors"
APP_PROFILE_RESOURCE = "applicationprofiles"
APP_RULE_RESOURCE = "applicationrules"

# IPsec VPNaaS Constants
IPSEC_VPN_SERVICE = 'ipsec/config'

# Dhcp constants
DHCP_SERVICE = "dhcp/config"
DHCP_BINDING_RESOURCE = "bindings"

# Syetem control constants
SYSCTL_SERVICE = 'systemcontrol/config'

# L2 gateway constants
BRIDGE = "bridging/config"

# IPAM constants
IPAM_POOL_SCOPE = "scope/globalroot-0"
IPAM_POOL_SERVICE = "ipam/pools"

# Self Signed Certificate constants
CSR = "csr"
CERTIFICATE = "certificate"

NETWORK_TYPES = ['Network', 'VirtualWire', 'DistributedVirtualPortgroup']

# Dynamic routing constants
ROUTING_CONFIG = "routing/config"
BGP_ROUTING_CONFIG = "routing/config/bgp"


def retry_upon_exception_exclude_error_codes(
    exc, excluded_errors, delay=0.5, max_delay=4, max_attempts=0):
    if not max_attempts:
        max_attempts = cfg.CONF.nsxv.retries
    return utils.retry_upon_exception_exclude_error_codes(
        exc, excluded_errors, delay, max_delay, max_attempts)


def retry_upon_exception(exc, delay=0.5, max_delay=4, max_attempts=0):
    if not max_attempts:
        max_attempts = cfg.CONF.nsxv.retries
    return utils.retry_upon_exception(exc, delay, max_delay, max_attempts)


class Vcns(object):

    def __init__(self, address, user, password, ca_file, insecure):
        self.address = address
        self.user = user
        self.password = password
        self.ca_file = ca_file
        self.insecure = insecure
        self.jsonapi_client = VcnsApiClient.VcnsApiHelper(address, user,
                                                          password,
                                                          format='json',
                                                          ca_file=ca_file,
                                                          insecure=insecure)
        self.xmlapi_client = VcnsApiClient.VcnsApiHelper(address, user,
                                                         password,
                                                         format='xml',
                                                         ca_file=ca_file,
                                                         insecure=insecure)
        self._nsx_version = None
        self._normalized_scoping_objects = None

    @retry_upon_exception(exceptions.ServiceConflict)
    def _client_request(self, client, method, uri,
                        params, headers, encodeParams):
        return client(method, uri, params, headers, encodeParams)

    def do_request(self, method, uri, params=None, format='json', **kwargs):
        msg = ("VcnsApiHelper('%(method)s', '%(uri)s', '%(body)s')" %
               {'method': method,
                'uri': uri,
                'body': jsonutils.dumps(params)})
        LOG.debug(strutils.mask_password(msg))

        headers = kwargs.get('headers')
        encodeParams = kwargs.get('encode', True)
        if format == 'json':
            _client = self.jsonapi_client.request
        else:
            _client = self.xmlapi_client.request

        ts = time.time()
        header, content = self._client_request(_client, method, uri, params,
                                               headers, encodeParams)
        te = time.time()

        LOG.debug('VcnsApiHelper reply: header=%(header)s content=%(content)s'
                  ' took %(seconds)2.4f',
                  {'header': header, 'content': content, 'seconds': te - ts})
        if content == '':
            return header, {}
        if kwargs.get('decode', True):
            content = jsonutils.loads(content)
        return header, content

    def edges_lock_operation(self):
        uri = URI_PREFIX + "?lockUpdatesOnEdge=true"
        return self.do_request(HTTP_POST, uri, decode=False)

    @retry_upon_exception(exceptions.ResourceNotFound)
    @retry_upon_exception(exceptions.RequestBad)
    def deploy_edge(self, request):
        uri = URI_PREFIX
        return self.do_request(HTTP_POST, uri, request, decode=False)

    def update_edge(self, edge_id, request):
        uri = "%s/%s" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, request, decode=False)

    def get_edge_id(self, job_id):
        uri = URI_PREFIX + "/jobs/%s" % job_id
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edge_jobs(self, edge_id):
        uri = URI_PREFIX + "/%s/jobs" % edge_id
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edge_deploy_status(self, edge_id):
        uri = URI_PREFIX + "/%s/status?getlatest=false" % edge_id
        return self.do_request(HTTP_GET, uri, decode="True")

    def delete_edge(self, edge_id):
        uri = "%s/%s" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_DELETE, uri)

    def add_vdr_internal_interface(self, edge_id, interface):
        uri = "%s/%s/interfaces?action=patch" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_POST, uri, interface, decode=True)

    def get_vdr_internal_interface(self, edge_id, interface_index):
        uri = "%s/%s/interfaces/%s" % (URI_PREFIX, edge_id, interface_index)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_vdr_internal_interface(self, edge_id,
                                      interface_index, interface):
        uri = "%s/%s/interfaces/%s" % (URI_PREFIX, edge_id, interface_index)
        return self.do_request(HTTP_PUT, uri, interface,
                               format='xml', decode=True)

    @retry_upon_exception(exceptions.RequestBad)
    def delete_vdr_internal_interface(self, edge_id, interface_index):
        uri = "%s/%s/interfaces/%d" % (URI_PREFIX, edge_id, interface_index)
        return self.do_request(HTTP_DELETE, uri, decode=True)

    def get_interfaces(self, edge_id):
        uri = "%s/%s/vnics" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    @retry_upon_exception(exceptions.RequestBad)
    def update_interface(self, edge_id, vnic):
        uri = "%s/%s/vnics/%d" % (URI_PREFIX, edge_id,
                                  vnic['index'])
        return self.do_request(HTTP_PUT, uri, vnic, decode=True)

    def delete_interface(self, edge_id, vnic_index):
        uri = "%s/%s/vnics/%d" % (URI_PREFIX, edge_id, vnic_index)
        return self.do_request(HTTP_DELETE, uri, decode=True)

    def get_nat_config(self, edge_id):
        uri = "%s/%s/nat/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_nat_config(self, edge_id, nat):
        uri = "%s/%s/nat/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, nat, decode=True)

    def delete_nat_rule(self, edge_id, rule_id):
        uri = "%s/%s/nat/config/rules/%s" % (URI_PREFIX, edge_id, rule_id)
        return self.do_request(HTTP_DELETE, uri, decode=True)

    def get_edge_status(self, edge_id):
        uri = "%s/%s/status?getlatest=false" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edge(self, edge_id):
        uri = "%s/%s" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def _get_edges(self, startindex=0):
        uri = '%s?startIndex=%d' % (URI_PREFIX, startindex)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edges(self):
        edges = []
        h, d = self._get_edges()
        edges.extend(d['edgePage']['data'])
        paging_info = d['edgePage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        count = int(paging_info['totalCount'])
        LOG.debug("There are total %s edges and page size is %s",
                  count, page_size)
        pages = count / page_size + 1
        for i in range(1, pages):
            start_index = page_size * i
            h, d = self._get_edges(start_index)
            edges.extend(d['edgePage']['data'])
        return edges

    def get_edge_syslog(self, edge_id):
        uri = "%s/%s/syslog/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_edge_syslog(self, edge_id, config):
        uri = "%s/%s/syslog/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, config)

    def delete_edge_syslog(self, edge_id):
        uri = "%s/%s/syslog/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_DELETE, uri)

    def update_edge_config_with_modifier(self, edge_id, module, modifier):
        uri = "%s/%s/%s/config" % (URI_PREFIX, edge_id, module)
        config = self.do_request(HTTP_GET, uri)[1]
        if modifier(config):
            return self.do_request(HTTP_PUT, uri, config)

    def get_edge_interfaces(self, edge_id):
        uri = "%s/%s/interfaces" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_routes(self, edge_id):
        uri = "%s/%s/routing/config/static" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri)

    def update_routes(self, edge_id, routes):
        uri = "%s/%s/routing/config/static" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, routes)

    def create_lswitch(self, lsconfig):
        uri = "/api/ws.v1/lswitch"
        return self.do_request(HTTP_POST, uri, lsconfig, decode=True)

    def delete_lswitch(self, lswitch_id):
        uri = "/api/ws.v1/lswitch/%s" % lswitch_id
        return self.do_request(HTTP_DELETE, uri)

    def get_loadbalancer_config(self, edge_id):
        uri = self._build_uri_path(edge_id, LOADBALANCER_SERVICE)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_loadbalancer_statistics(self, edge_id):
        uri = self._build_uri_path(edge_id, LOADBALANCER_STATS)
        return self.do_request(HTTP_GET, uri, decode=True)

    def enable_service_loadbalancer(self, edge_id, config):
        uri = self._build_uri_path(edge_id, LOADBALANCER_SERVICE)
        return self.do_request(HTTP_PUT, uri, config)

    def sync_firewall(self):
        for cluster_id in cfg.CONF.nsxv.cluster_moid:
            uri = '/api/4.0/firewall/forceSync/%s' % cluster_id
            self.do_request(HTTP_POST, uri)

    def update_firewall(self, edge_id, fw_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE)
        return self.do_request(HTTP_PUT, uri, fw_req)

    def delete_firewall(self, edge_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE, None)
        return self.do_request(HTTP_DELETE, uri)

    def update_firewall_rule(self, edge_id, vcns_rule_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_PUT, uri, fwr_req)

    def delete_firewall_rule(self, edge_id, vcns_rule_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_DELETE, uri)

    def add_firewall_rule_above(self, edge_id, ref_vcns_rule_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE)
        uri += "?aboveRuleId=" + ref_vcns_rule_id
        return self.do_request(HTTP_POST, uri, fwr_req)

    def add_firewall_rule(self, edge_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE)
        return self.do_request(HTTP_POST, uri, fwr_req)

    def update_firewall_default_policy(self, edge_id, fw_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE, 'defaultpolicy')
        return self.do_request(HTTP_PUT, uri, fw_req)

    def get_firewall(self, edge_id):
        uri = self._build_uri_path(edge_id, FIREWALL_SERVICE)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_firewall_rule(self, edge_id, vcns_rule_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    #
    #Edge LBAAS call helper
    #
    def create_vip(self, edge_id, vip_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE)
        return self.do_request(HTTP_POST, uri, vip_new)

    def get_vip(self, edge_id, vip_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_vip(self, edge_id, vip_vseid, vip_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_PUT, uri, vip_new)

    def delete_vip(self, edge_id, vip_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_pool(self, edge_id, pool_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE)
        return self.do_request(HTTP_POST, uri, pool_new)

    def get_pool(self, edge_id, pool_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_pool(self, edge_id, pool_vseid, pool_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_PUT, uri, pool_new)

    def delete_pool(self, edge_id, pool_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_health_monitor(self, edge_id, monitor_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE)
        return self.do_request(HTTP_POST, uri, monitor_new)

    def get_health_monitor(self, edge_id, monitor_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE, monitor_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_health_monitor(self, edge_id, monitor_vseid, monitor_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE,
            monitor_vseid)
        return self.do_request(HTTP_PUT, uri, monitor_new)

    def delete_health_monitor(self, edge_id, monitor_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE,
            monitor_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_app_profile(self, edge_id, app_profile):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE)
        return self.do_request(HTTP_POST, uri, app_profile)

    def update_app_profile(self, edge_id, app_profileid, app_profile):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE, app_profileid)
        return self.do_request(HTTP_PUT, uri, app_profile)

    def delete_app_profile(self, edge_id, app_profileid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE,
            app_profileid)
        return self.do_request(HTTP_DELETE, uri)

    def create_app_rule(self, edge_id, app_rule):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_RULE_RESOURCE)
        return self.do_request(HTTP_POST, uri, app_rule)

    def update_app_rule(self, edge_id, app_ruleid, app_rule):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_RULE_RESOURCE, app_ruleid)
        return self.do_request(HTTP_PUT, uri, app_rule)

    def delete_app_rule(self, edge_id, app_ruleid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_RULE_RESOURCE,
            app_ruleid)
        return self.do_request(HTTP_DELETE, uri)

    def update_ipsec_config(self, edge_id, ipsec_config):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_PUT, uri, ipsec_config)

    def delete_ipsec_config(self, edge_id):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_DELETE, uri)

    def get_ipsec_config(self, edge_id):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_GET, uri)

    @retry_upon_exception(exceptions.RequestBad)
    def create_virtual_wire(self, vdn_scope_id, request):
        """Creates a VXLAN virtual wire

        The method will return the virtual wire ID.
        """
        uri = '/api/2.0/vdn/scopes/%s/virtualwires' % vdn_scope_id
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def delete_virtual_wire(self, virtualwire_id):
        """Deletes a virtual wire."""
        uri = '/api/2.0/vdn/virtualwires/%s' % virtualwire_id
        return self.do_request(HTTP_DELETE, uri, format='xml')

    def create_port_group(self, dvs_id, request):
        """Creates a port group on a DVS

        The method will return the port group ID.
        """
        uri = '/api/2.0/xvs/switches/%s/networks' % dvs_id
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def delete_port_group(self, dvs_id, portgroup_id):
        """Deletes a portgroup."""
        uri = '/api/2.0/xvs/switches/%s/networks/%s' % (dvs_id,
                                                        portgroup_id)
        return self.do_request(HTTP_DELETE, uri, format='xml', decode=False)

    def get_vdn_switch(self, dvs_id):
        uri = '/api/2.0/vdn/switches/%s' % dvs_id
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_vdn_switch(self, switch):
        uri = '/api/2.0/vdn/switches'
        return self.do_request(HTTP_PUT, uri, switch)

    def query_interface(self, edge_id, vnic_index):
        uri = "%s/%s/vnics/%d" % (URI_PREFIX, edge_id, vnic_index)
        return self.do_request(HTTP_GET, uri, decode=True)

    def reconfigure_dhcp_service(self, edge_id, request_config):
        """Reconfigure dhcp static bindings in the created Edge."""
        uri = "/api/4.0/edges/%s/dhcp/config" % edge_id

        return self.do_request(HTTP_PUT, uri, request_config)

    def query_dhcp_configuration(self, edge_id):
        """Query DHCP configuration from the specific edge."""
        uri = "/api/4.0/edges/%s/dhcp/config" % edge_id
        return self.do_request(HTTP_GET, uri)

    def create_dhcp_binding(self, edge_id, request_config):
        """Append one dhcp static binding on the edge."""
        uri = self._build_uri_path(edge_id,
                                   DHCP_SERVICE, DHCP_BINDING_RESOURCE)
        return self.do_request(HTTP_POST, uri, request_config, decode=False)

    def delete_dhcp_binding(self, edge_id, binding_id):
        """Delete one dhcp static binding on the edge."""
        uri = self._build_uri_path(edge_id,
                                   DHCP_SERVICE, DHCP_BINDING_RESOURCE,
                                   binding_id)
        return self.do_request(HTTP_DELETE, uri, decode=False)

    def get_dhcp_binding(self, edge_id, binding_id):
        """Get a dhcp static binding from the edge."""
        uri = self._build_uri_path(edge_id,
                                   DHCP_SERVICE, DHCP_BINDING_RESOURCE,
                                   binding_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def create_security_group(self, request):
        """Creates a security group container in nsx.

        The method will return the security group ID.
        """
        uri = '%s/globalroot-0' % (SECURITYGROUP_PREFIX)
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def delete_security_group(self, securitygroup_id):
        """Deletes a security group container."""
        uri = '%s/%s?force=true' % (SECURITYGROUP_PREFIX, securitygroup_id)
        return self.do_request(HTTP_DELETE, uri, format='xml', decode=False)

    def update_security_group(self, sg_id, sg_name, description):
        """Updates the NSXv security group name."""
        uri = '%s/%s' % (SECURITYGROUP_PREFIX, sg_id)
        h, c = self.do_request(HTTP_GET, uri, format='xml', decode=False)
        sg = et.fromstring(c)
        sg.find('name').text = sg_name
        sg.find('description').text = description
        return self.do_request(HTTP_PUT, uri, et.tostring(sg),
                               format='xml', decode=False, encode=False)

    def list_security_groups(self):
        uri = '%s/scope/globalroot-0' % SECURITYGROUP_PREFIX
        return self.do_request(HTTP_GET, uri, format='xml', decode=False)

    def get_security_group_id(self, sg_name):
        """Returns NSXv security group id which match the given name."""
        h, secgroups = self.list_security_groups()
        root = utils.normalize_xml(secgroups)
        for sg in root.iter('securitygroup'):
            if sg.find('name').text == sg_name:
                return sg.find('objectId').text

    @retry_upon_exception(exceptions.VcnsApiException)
    def create_bridge(self, edge_id, request):
        """Create a bridge."""
        uri = self._build_uri_path(edge_id, BRIDGE)
        return self.do_request(HTTP_PUT, uri, request, format='xml',
                               decode=False)

    @retry_upon_exception(exceptions.VcnsApiException)
    def delete_bridge(self, edge_id):
        """Delete a bridge."""
        uri = self._build_uri_path(edge_id, BRIDGE)
        return self.do_request(HTTP_DELETE, uri, format='xml', decode=False)

    def create_redirect_section(self, request):
        """Creates a layer 3 redirect section in nsx rule table.

        The method will return the uri to newly created section.
        """
        sec_type = FIREWALL_REDIRECT_SEC_TYPE
        uri = '%s/%s?autoSaveDraft=false' % (FIREWALL_PREFIX, sec_type)
        uri += '&operation=insert_before&anchorId=1002'
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False, encode=False)

    def create_section(self, type, request,
                       insert_top=False, insert_before=None):
        """Creates a layer 3 or layer 2 section in nsx rule table.

        The method will return the uri to newly created section.
        """
        if type == 'ip':
            sec_type = 'layer3sections'
        else:
            sec_type = 'layer2sections'
        uri = '%s/%s?autoSaveDraft=false' % (FIREWALL_PREFIX, sec_type)
        if insert_top:
            uri += '&operation=insert_top'
        # We want to place security-group sections before the default cluster
        # section, and we want to place the default cluster section before the
        # global default section.
        elif insert_before:
            uri += '&operation=insert_before&anchorId=%s' % insert_before
        else:
            uri += '&operation=insert_before&anchorId=1003'
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False, encode=False)

    def update_section(self, section_uri, request, h):
        """Replaces a section in nsx rule table."""
        uri = '%s?autoSaveDraft=false' % section_uri
        headers = self._get_section_header(section_uri, h)
        return self.do_request(HTTP_PUT, uri, request, format='xml',
                               decode=False, encode=False, headers=headers)

    def delete_section(self, section_uri):
        """Deletes a section in nsx rule table."""
        uri = '%s?autoSaveDraft=false' % section_uri
        return self.do_request(HTTP_DELETE, uri, format='xml', decode=False)

    def get_section(self, section_uri):
        return self.do_request(HTTP_GET, section_uri, format='xml',
                               decode=False)

    def get_default_l3_id(self):
        """Retrieve the id of the default l3 section."""
        h, firewall_config = self.get_dfw_config()
        root = utils.normalize_xml(firewall_config)
        for child in root:
            if str(child.tag) == 'layer3Sections':
                sections = list(child.iter('section'))
                default = sections[-1]
                return default.attrib['id']

    def get_dfw_config(self):
        uri = FIREWALL_PREFIX
        return self.do_request(HTTP_GET, uri, decode=False, format='xml')

    def update_dfw_config(self, request, h):
        uri = FIREWALL_PREFIX
        headers = self._get_section_header(None, h)
        return self.do_request(HTTP_PUT, uri, request, format='xml',
                               decode=False, encode=False, headers=headers)

    def get_section_id(self, section_name):
        """Retrieve the id of a section from nsx."""
        h, firewall_config = self.get_dfw_config()
        root = utils.normalize_xml(firewall_config)
        for sec in root.iter('section'):
            if sec.attrib['name'] == section_name:
                return sec.attrib['id']

    def update_section_by_id(self, id, type, request):
        """Update a section while building its uri from the id."""
        if type == 'ip':
            sec_type = 'layer3sections'
        else:
            sec_type = 'layer2sections'
        section_uri = '%s/%s/%s' % (FIREWALL_PREFIX, sec_type, id)
        self.update_section(section_uri, request, h=None)

    def _get_section_header(self, section_uri, h=None):
        if h is None:
            h, c = self.do_request(HTTP_GET, section_uri, format='xml',
                                   decode=False)
        etag = h['etag']
        headers = {'If-Match': etag}
        return headers

    def remove_rule_from_section(self, section_uri, rule_id):
        """Deletes a rule from nsx section table."""
        uri = '%s/rules/%s?autoSaveDraft=false' % (section_uri, rule_id)
        headers = self._get_section_header(section_uri)
        return self.do_request(HTTP_DELETE, uri, format='xml',
                               headers=headers)

    @retry_upon_exception(exceptions.RequestBad)
    def add_member_to_security_group(self, security_group_id, member_id):
        """Adds a vnic member to nsx security group."""
        uri = '%s/%s/members/%s?failIfExists=false' % (
            SECURITYGROUP_PREFIX, security_group_id, member_id)
        return self.do_request(HTTP_PUT, uri, format='xml', decode=False)

    def remove_member_from_security_group(self, security_group_id,
                                          member_id):
        """Removes a vnic member from nsx security group."""
        uri = '%s/%s/members/%s?failIfAbsent=false' % (
            SECURITYGROUP_PREFIX, security_group_id, member_id)
        return self.do_request(HTTP_DELETE, uri, format='xml', decode=False)

    def set_system_control(self, edge_id, prop):
        uri = self._build_uri_path(edge_id, SYSCTL_SERVICE)

        payload = {
            'featureType': 'systemcontrol',
            'property': prop
        }
        return self.do_request(HTTP_PUT, uri, payload, decode=True)

    def get_system_control(self, edge_id):
        uri = self._build_uri_path(edge_id, SYSCTL_SERVICE)

        return self.do_request(HTTP_GET, uri)

    def _get_enforcement_point_body(self, enforcement_points):
        e_point_list = []
        for enforcement_point in enforcement_points:
            e_point_list.append({
                'enforcementPoint': {
                    'id': enforcement_point,
                    'type': enforcement_point.split('-')[0]
                }
            })
        return {'__enforcementPoints': e_point_list}

    @retry_upon_exception_exclude_error_codes(
        exceptions.RequestBad, [constants.NSX_ERROR_ALREADY_HAS_SG_POLICY])
    def create_spoofguard_policy(self, enforcement_points, name, enable):
        uri = '%s/policies/' % SPOOFGUARD_PREFIX

        body = {'spoofguardPolicy':
                {'name': name,
                 'operationMode': 'MANUAL' if enable else 'DISABLE',
                 'allowLocalIPs': 'true'}}
        body['spoofguardPolicy'].update(
            self._get_enforcement_point_body(enforcement_points))
        return self.do_request(HTTP_POST, uri, body,
                               format='xml', encode=True, decode=False)

    @retry_upon_exception(exceptions.RequestBad)
    def update_spoofguard_policy(self, policy_id,
                                 enforcement_points, name, enable):
        update_uri = '%s/policies/%s' % (SPOOFGUARD_PREFIX, policy_id)
        publish_uri = '%s/%s?action=publish' % (SPOOFGUARD_PREFIX, policy_id)

        body = {'spoofguardPolicy':
                {'policyId': policy_id,
                 'name': name,
                 'operationMode': 'MANUAL' if enable else 'DISABLE',
                 'allowLocalIPs': 'true'}}
        body['spoofguardPolicy'].update(
            self._get_enforcement_point_body(enforcement_points))

        self.do_request(HTTP_PUT, update_uri, body,
                        format='xml', encode=True, decode=False)
        return self.do_request(HTTP_POST, publish_uri, decode=False)

    @retry_upon_exception(exceptions.RequestBad)
    def delete_spoofguard_policy(self, policy_id):
        uri = '%s/policies/%s' % (SPOOFGUARD_PREFIX, policy_id)
        return self.do_request(HTTP_DELETE, uri, decode=False)

    def get_spoofguard_policy(self, policy_id):
        uri = '%s/policies/%s' % (SPOOFGUARD_PREFIX, policy_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_spoofguard_policies(self):
        uri = '%s/policies/' % SPOOFGUARD_PREFIX
        return self.do_request(HTTP_GET, uri, decode=True)

    def _approve_assigned_addresses(self, policy_id,
                                    vnic_id, mac_addr, addresses):
        uri = '%s/%s' % (SPOOFGUARD_PREFIX, policy_id)
        addresses = [{'ipAddress': ip_addr} for ip_addr in addresses]
        body = {'spoofguardList':
                {'spoofguard':
                 {'id': vnic_id,
                  'vnicUuid': vnic_id,
                  'approvedIpAddress': addresses,
                  'approvedMacAddress': mac_addr,
                  'publishedIpAddress': addresses,
                  'publishedMacAddress': mac_addr}}}

        return self.do_request(HTTP_POST, '%s?action=approve' % uri,
                               body, format='xml', decode=False)

    @retry_upon_exception(exceptions.RequestBad)
    def approve_assigned_addresses(self, policy_id,
                                   vnic_id, mac_addr, addresses):
        return self._approve_assigned_addresses(
            policy_id, vnic_id, mac_addr, addresses)

    @retry_upon_exception(exceptions.VcnsApiException)
    def publish_assigned_addresses(self, policy_id, vnic_id):
        uri = '%s/%s' % (SPOOFGUARD_PREFIX, policy_id)
        publish_vnic_uri = '%s?action=publish&vnicId=%s' % (uri, vnic_id)
        return self.do_request(HTTP_POST, publish_vnic_uri, decode=False)

    def inactivate_vnic_assigned_addresses(self, policy_id, vnic_id):
        try:
            self._approve_assigned_addresses(policy_id, vnic_id, '', [])
        except exceptions.RequestBad:
            LOG.debug("Request failed: inactivate vnic %s assigned addresses",
                      vnic_id)
        else:
            return self.publish_assigned_addresses(policy_id, vnic_id)

    def _build_uri_path(self, edge_id,
                        service,
                        resource=None,
                        resource_id=None,
                        parent_resource_id=None,
                        fields=None,
                        relations=None,
                        filters=None,
                        types=None,
                        is_attachment=False,
                        is_async=False):
        uri_prefix = "%s/%s/%s" % (URI_PREFIX, edge_id, service)
        if resource:
            res_path = resource + (resource_id and "/%s" % resource_id or '')
            uri_path = "%s/%s" % (uri_prefix, res_path)
        else:
            uri_path = uri_prefix
        if is_async:
            return (uri_path + "?async=true")
        else:
            return uri_path

    def add_vm_to_exclude_list(self, vm_id):
        uri = '%s/%s' % (EXCLUDELIST_PREFIX, vm_id)
        return self.do_request(HTTP_PUT, uri)

    def delete_vm_from_exclude_list(self, vm_id):
        uri = '%s/%s' % (EXCLUDELIST_PREFIX, vm_id)
        return self.do_request(HTTP_DELETE, uri)

    def get_scoping_objects(self):
        uri = '%s/usermgmt/scopingobjects' % SERVICES_PREFIX
        h, scoping_objects = self.do_request(HTTP_GET, uri, decode=False,
                                             format='xml')
        return scoping_objects

    def _scopingobjects_lookup(self, type_names, object_id, name=None,
                               use_cache=False):
        """Look for a specific object in the NSX scoping objects."""
        # used cached scoping objects during plugin init since it is
        # a big structure to retrieve and parse each time.
        if use_cache and self._normalized_scoping_objects is not None:
            # Use the cached data
            root = self._normalized_scoping_objects
        else:
            # Not using cache, or we do want to use it,
            # but it was not saved yet:
            # So get the data from the NSX and parse it
            so_list = self.get_scoping_objects()
            root = utils.normalize_xml(so_list)
            # Save it for possible usage next time (even if not using cache)
            self._normalized_scoping_objects = root

        for obj in root.iter('object'):
            if (obj.find('objectTypeName').text in type_names and
                    obj.find('objectId').text == object_id and
                    (name is None or obj.find('name').text == name)):
                return True

        return False

    def validate_datacenter_moid(self, object_id, during_init=False):
        return self._scopingobjects_lookup(['Datacenter'], object_id,
                                           use_cache=during_init)

    def validate_network(self, object_id, during_init=False):
        return self._scopingobjects_lookup(NETWORK_TYPES, object_id,
                                           use_cache=during_init)

    def validate_network_name(self, object_id, name, during_init=False):
        return self._scopingobjects_lookup(NETWORK_TYPES, object_id,
                                           name=name, use_cache=during_init)

    def validate_vdn_scope(self, object_id):
        uri = '%s/scopes' % VDN_PREFIX
        h, scope_list = self.do_request(HTTP_GET, uri, decode=False,
                                        format='xml')
        root = utils.normalize_xml(scope_list)
        for obj_id in root.iter('objectId'):
            if obj_id.text == object_id:
                return True

        return False

    def get_dvs_list(self):
        uri = '%s/switches' % VDN_PREFIX
        h, dvs_list = self.do_request(HTTP_GET, uri, decode=False,
                                      format='xml')
        root = utils.normalize_xml(dvs_list)
        dvs_list = []
        for obj_id in root.iter('objectId'):
            if obj_id.text:
                dvs_list.append(obj_id.text)

        return dvs_list

    def validate_dvs(self, object_id, dvs_list=None):
        if not dvs_list:
            dvs_list = self.get_dvs_list()
        for dvs in dvs_list:
            if dvs == object_id:
                return True

        return False

    def validate_inventory(self, object_id):
        uri = '%s/inventory/%s/basicinfo' % (SERVICES_PREFIX, object_id)
        try:
            h, c = self.do_request(HTTP_GET, uri, decode=False)
        except exceptions.ResourceNotFound:
            return False
        return True

    def get_inventory_name(self, object_id):
        uri = '%s/inventory/%s/basicinfo' % (SERVICES_PREFIX, object_id)
        h, c = self.do_request(HTTP_GET, uri, decode=True)
        return c['name']

    def _get_version(self):
        uri = '/api/2.0/services/vsmconfig'
        h, c = self.do_request(HTTP_GET, uri, decode=True)
        version = c['version']
        LOG.debug("NSX Version: %s", version)
        return version

    def get_version(self):
        if self._nsx_version is None:
            try:
                self._nsx_version = self._get_version()
            except Exception as e:
                # Versions prior to 6.2.0 do not support the above API
                LOG.error("Unable to get NSX version. Exception: %s", e)
                # Minimum supported version is 6.1
                self._nsx_version = '6.1'
        return self._nsx_version

    def get_tuning_configration(self):
        uri = '/api/4.0/edgePublish/tuningConfiguration'
        h, c = self.do_request(HTTP_GET, uri, decode=True)
        return c

    def configure_aggregate_publishing(self):
        uri = "/api/4.0/edgePublish/tuningConfiguration"
        # Ensure that configured values are not changed
        config = self.get_tuning_configration()
        LOG.debug("Tuning configuration: %s", config)
        tuning = et.Element('tuningConfiguration')
        for opt, val in six.iteritems(config):
            child = et.Element(opt)
            if opt == 'aggregatePublishing':
                child.text = 'true'
            else:
                child.text = str(val)
            tuning.append(child)
        return self.do_request(HTTP_PUT, uri, et.tostring(tuning),
                               format='xml', decode=True)

    def configure_reservations(self):
        uri = "/api/4.0/edgePublish/tuningConfiguration"
        config = self.get_tuning_configration()
        tuning = et.Element('tuningConfiguration')
        for opt, val in six.iteritems(config):
            child = et.Element(opt)
            if (opt == 'edgeVCpuReservationPercentage' or
                opt == 'edgeMemoryReservationPercentage'):
                child.text = '0'
            elif opt == 'megaHertzPerVCpu':
                child.text = '1500'
            else:
                child.text = str(val)
            tuning.append(child)
        return self.do_request(HTTP_PUT, uri, et.tostring(tuning),
                               format='xml', decode=True)

    def enable_ha(self, edge_id, request_config):
        """Enable HA in the given edge."""
        uri = "/api/4.0/edges/%s/highavailability/config" % edge_id
        return self.do_request(HTTP_PUT, uri, request_config)

    def change_edge_appliance_size(self, edge_id, size):
        """Change the size of edge appliances."""
        uri = ("/api/4.0/edges/%s/appliances/?size=%s" %
               (edge_id, size))
        return self.do_request(HTTP_POST, uri)

    def change_edge_appliance(self, edge_id, request):
        uri = "/api/4.0/edges/%s/appliances" % edge_id
        return self.do_request(HTTP_PUT, uri, request)

    def get_edge_appliances(self, edge_id):
        uri = "/api/4.0/edges/%s/appliances" % edge_id
        return self.do_request(HTTP_GET, uri)

    def upload_edge_certificate(self, edge_id, request):
        """Creates a certificate on the specified Edge appliance."""
        uri = '%s/%s/%s' % (TRUSTSTORE_PREFIX, CERTIFICATE, edge_id)
        return self.do_request(HTTP_POST, uri, request, decode=True)

    def create_csr(self, edge_id, request=nsxv_constants.CSR_REQUEST):
        """Create a CSR on the specified Edge appliance."""
        uri = '%s/%s/%s' % (TRUSTSTORE_PREFIX, CSR, edge_id)
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def create_csr_cert(self, csr_id):
        """Create a CSR self signed cert on the specified Edge appliance."""
        uri = '%s/%s/%s?noOfDays=%s' % (TRUSTSTORE_PREFIX, CSR, csr_id,
                                        nsxv_constants.CERT_NUMBER_OF_DAYS)
        return self.do_request(HTTP_PUT, uri)

    def get_service_insertion_profile(self, profile_id):
        profiles_uri = '%s/%s' % (SERVICE_INSERTION_PROFILE_PREFIX, profile_id)
        return self.do_request(HTTP_GET, profiles_uri, format='xml',
                               decode=False)

    def update_service_insertion_profile_binding(self, profile_id, request):
        profiles_uri = '%s/%s/%s' % (SERVICE_INSERTION_PROFILE_PREFIX,
                                     profile_id, 'binding')
        return self.do_request(HTTP_POST, profiles_uri, request, format='xml',
                               decode=False)

    def create_ipam_ip_pool(self, request):
        uri = '%s/%s/%s' % (SERVICES_PREFIX, IPAM_POOL_SERVICE,
                            IPAM_POOL_SCOPE)
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def delete_ipam_ip_pool(self, pool_id):
        uri = '%s/%s/%s' % (SERVICES_PREFIX, IPAM_POOL_SERVICE, pool_id)
        return self.do_request(HTTP_DELETE, uri)

    def get_ipam_ip_pool(self, pool_id):
        uri = '%s/%s/%s' % (SERVICES_PREFIX, IPAM_POOL_SERVICE, pool_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def allocate_ipam_ip_from_pool(self, pool_id, ip_addr=None):
        uri = '%s/%s/%s/%s' % (SERVICES_PREFIX, IPAM_POOL_SERVICE, pool_id,
                               'ipaddresses')
        if ip_addr:
            request = {'ipAddressRequest': {'allocationMode': 'RESERVE',
                                            'ipAddress': ip_addr}}
        else:
            request = {'ipAddressRequest': {'allocationMode': 'ALLOCATE'}}
        return self.do_request(HTTP_POST, uri, request, format='xml',
                               decode=False)

    def release_ipam_ip_to_pool(self, pool_id, ip_addr):
        uri = '%s/%s/%s/%s/%s' % (SERVICES_PREFIX, IPAM_POOL_SERVICE, pool_id,
                               'ipaddresses', ip_addr)
        return self.do_request(HTTP_DELETE, uri)

    def get_security_policy(self, policy_id, return_xml=True):
        # get the policy configuration as an xml string / dictionary
        uri = '%s/%s' % (SECURITY_POLICY_PREFIX, policy_id)
        if return_xml:
            format = 'xml'
            decode = False
        else:
            format = 'json'
            decode = True
        h, policy = self.do_request(HTTP_GET, uri, format=format,
                                    decode=decode)
        return policy

    def update_security_policy(self, policy_id, request):
        # update the policy configuration. request should be an xml string
        uri = '%s/%s' % (SECURITY_POLICY_PREFIX, policy_id)
        return self.do_request(HTTP_PUT, uri, request,
                               format='xml',
                               decode=False, encode=True)

    def get_security_policies(self):
        # get the policies configuration dictionary
        uri = '%s/all' % (SECURITY_POLICY_PREFIX)
        h, policies = self.do_request(HTTP_GET, uri, decode=True)
        return policies

    def list_applications(self):
        uri = '%s/scope/globalroot-0' % APPLICATION_PREFIX
        h, apps = self.do_request(HTTP_GET, uri, decode=True)
        return apps

    def update_edge_routing_config(self, edge_id, request_config):
        uri = self._build_uri_path(edge_id, ROUTING_CONFIG)
        return self.do_request(HTTP_PUT, uri,
                               VcnsApiClient.xmldumps(request_config),
                               format='xml')

    def get_edge_routing_config(self, edge_id):
        uri = self._build_uri_path(edge_id, ROUTING_CONFIG)
        return self.do_request(HTTP_GET, uri)

    def update_bgp_dynamic_routing(self, edge_id, bgp_request):
        uri = self._build_uri_path(edge_id, BGP_ROUTING_CONFIG)
        return self.do_request(HTTP_PUT, uri,
                               VcnsApiClient.xmldumps(bgp_request),
                               format='xml')

    def get_bgp_routing_config(self, edge_id):
        uri = self._build_uri_path(edge_id, BGP_ROUTING_CONFIG)
        return self.do_request(HTTP_GET, uri)

    def delete_bgp_routing_config(self, edge_id):
        uri = self._build_uri_path(edge_id, BGP_ROUTING_CONFIG)
        return self.do_request(HTTP_DELETE, uri)
