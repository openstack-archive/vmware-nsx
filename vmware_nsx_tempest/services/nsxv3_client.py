# Copyright 2016 VMware Inc
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

import base64
import requests

from oslo_log import log as logging
from oslo_serialization import jsonutils

from vmware_nsx_tempest._i18n import _LE
from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW

requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


class NSXV3Client(object):
    """Base NSXv3 REST client"""
    API_VERSION = "v1"

    def __init__(self, host, username, password, *args, **kwargs):
        self.host = host
        self.username = username
        self.password = password
        self.version = None
        self.endpoint = None
        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.headers = None
        self.api_version = NSXV3Client.API_VERSION

        self.__set_headers()

    def __set_endpoint(self, endpoint):
        self.endpoint = endpoint

    def get_endpoint(self):
        return self.endpoint

    def __set_content_type(self, content_type):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type

    def __set_accept_type(self, accept_type):
        self.accept_type = accept_type

    def get_accept_type(self):
        return self.accept_type

    def __set_api_version(self, api_version):
        self.api_version = api_version

    def get_api_version(self):
        return self.api

    def __set_url(self, api=None, secure=None, host=None, endpoint=None):
        api = self.api_version if api is None else api
        secure = self.secure if secure is None else secure
        host = self.host if host is None else host
        endpoint = self.endpoint if endpoint is None else endpoint
        http_type = 'https' if secure else 'http'
        self.url = '%s://%s/api/%s%s' % (http_type, host, api, endpoint)

    def get_url(self):
        return self.url

    def __set_headers(self, content=None, accept=None):
        content_type = self.content_type if content is None else content
        accept_type = self.accept_type if accept is None else accept
        auth_cred = self.username + ":" + self.password
        auth = base64.b64encode(auth_cred)
        headers = {}
        headers['Authorization'] = "Basic %s" % auth
        headers['Content-Type'] = content_type
        headers['Accept'] = accept_type
        self.headers = headers

    def get(self, endpoint=None, params=None):
        """
        Basic query method for json API request
        """
        self.__set_url(endpoint=endpoint)
        response = requests.get(self.url, headers=self.headers,
                                verify=self.verify, params=params)
        return response

    def put(self, endpoint=None, body=None):
        """
        Basic put API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.put(self.url, headers=self.headers,
                                verify=self.verify, data=jsonutils.dumps(body))
        return response

    def delete(self, endpoint=None, params=None):
        """
        Basic delete API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.delete(self.url, headers=self.headers,
                                   verify=self.verify, params=params)
        return response

    def post(self, endpoint=None, body=None):
        """
        Basic post API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.post(self.url, headers=self.headers,
                                 verify=self.verify,
                                 data=jsonutils.dumps(body))
        return response

    def get_transport_zones(self):
        """
        Retrieve all transport zones
        """
        response = self.get(endpoint="/transport-zones")
        return response.json()['results']

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        response = self.get(endpoint="/logical-ports")
        return response.json()['results']

    def get_os_logical_ports(self):
        """
        Retrieve all logical ports created from OpenStack
        """
        lports = self.get_logical_ports()
        return self.get_os_resources(lports)

    def update_logical_port_attachment(self, lports):
        """
        Update the logical port attachment

        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            p['attachment'] = None
            endpoint = "/logical-ports/%s" % p['id']
            response = self.put(endpoint=endpoint, body=p)
            if response.status_code != requests.codes.ok:
                LOG.error(_LE("Failed to update lport %s"), p['id'])

    def cleanup_os_logical_ports(self):
        """
        Delete all logical ports created by OpenStack
        """
        lports = self.get_logical_ports()
        os_lports = self.get_os_resources(lports)
        LOG.info(_LI("Number of OS Logical Ports to be deleted: %s"),
                 len(os_lports))
        # logical port vif detachment
        self.update_logical_port_attachment(os_lports)
        for p in os_lports:
            endpoint = '/logical-ports/%s' % p['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                LOG.info(_LI("Successfully deleted logical port %s"), p['id'])
            else:
                LOG.error(_LE("Failed to delete lport %(port_id)s, response "
                              "code %(code)s"),
                          {'port_id': p['id'], 'code': response.status_code})

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-project-id' in tag.values()]
        return os_resources

    def get_nsx_resource_by_name(self, nsx_resources, nsx_name):
        """
        Get the NSX component created from OpenStack by name.

        The name should be converted from os_name to nsx_name.
        If found exact one match return it, otherwise report error.
        """
        nsx_resource = [n for n in nsx_resources if
                        n['display_name'] == nsx_name]
        if len(nsx_resource) == 0:
            LOG.warning(_LW("Backend nsx resource %s NOT found!"), nsx_name)
            return None
        if len(nsx_resource) > 1:
            LOG.error(_LE("More than 1 nsx resources found: %s!"),
                      nsx_resource)
            return None
        else:
            LOG.info(_LI("Found nsgroup: %s"), nsx_resource[0])
            return nsx_resource[0]

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        response = self.get(endpoint="/logical-switches")
        return response.json()['results']

    def get_bridge_cluster_info(self):
        """
        Get bridge cluster information.

        :return: returns bridge cluster id and bridge cluster name.
        """
        response = self.get(endpoint="/bridge-clusters")
        return response.json()["results"]

    def get_logical_switch(self, os_name, os_uuid):
        """
        Get the logical switch based on the name and uuid provided.

        The name of the logical switch should follow
            <os_network_name>_<first 5 os uuid>...<last 5 os uuid>
        Return logical switch if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error(_LE("Name and uuid of OpenStack L2 network need to be "
                          "present in order to query backend logical switch!"))
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        lswitches = self.get_logical_switches()
        return self.get_nsx_resource_by_name(lswitches, nsx_name)

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] is ls_id]

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        response = self.get(endpoint="/firewall/sections")
        return response.json()['results']

    def get_firewall_section(self, os_name, os_uuid):
        """
        Get the firewall section by os_name and os_uuid
        """
        if not os_name or not os_uuid:
            LOG.error(_LE("Name and uuid of OS security group should be "
                          "present in order to query backend FW section "
                          "created"))
            return None
        nsx_name = os_name + " - " + os_uuid
        fw_sections = self.get_firewall_sections()
        return self.get_nsx_resource_by_name(fw_sections, nsx_name)

    def get_firewall_section_rules(self, fw_section):
        """
        Retrieve all fw rules for a given fw section
        """
        endpoint = "/firewall/sections/%s/rules" % fw_section['id']
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def get_firewall_section_rule(self, fw_section, os_uuid):
        """
        Get the firewall section rule based on the name
        """
        fw_rules = self.get_firewall_section_rules(fw_section)
        nsx_name = os_uuid
        return self.get_nsx_resource_by_name(fw_rules, nsx_name)

    def get_ns_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        response = self.get(endpoint="/ns-groups")
        return response.json()['results']

    def get_ns_group(self, os_name, os_uuid):
        """
        Get the NSGroup based on the name provided.
        The name of the nsgroup should follow
            <os_sg_name> - <os_sg_uuid>
        Return nsgroup if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error(_LE("Name and uuid of OS security group should be "
                          "present in order to query backend nsgroup created"))
            return None
        nsx_name = os_name + " - " + os_uuid
        nsgroups = self.get_ns_groups()
        return self.get_nsx_resource_by_name(nsgroups, nsx_name)

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        if tier:
            endpoint = "/logical-routers?router_type=%s" % tier
        else:
            endpoint = "/logical-routers"
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def get_logical_router(self, os_name, os_uuid):
        """
        Get the logical router based on the os_name and os_uuid provided.
        The name of the logical router shoud follow
            <os_router_name>_<starting_5_uuid>...<trailing_5_uuid>
        Return the logical router if found, otherwise return None.
        """
        if not os_name or not os_uuid:
            LOG.error(_LE("Name and uuid of OS router should be present "
                          "in order to query backend logical router created"))
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        lrouters = self.get_logical_routers()
        return self.get_nsx_resource_by_name(lrouters, nsx_name)

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        endpoint = "/logical-router-ports?logical_router_id=%s" % lrouter['id']
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def get_logical_router_nat_rules(self, lrouter):
        """
        Get all user defined NAT rules of the specific logical router
        """
        if not lrouter:
            LOG.error(_LE("Logical router needs to be present in order "
                          "to get the NAT rules"))
            return None
        endpoint = "/logical-routers/%s/nat/rules" % lrouter['id']
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def get_logical_dhcp_servers(self):
        """
        Get all logical DHCP servers on NSX backend
        """
        response = self.get(endpoint="/dhcp/servers")
        return response.json()['results']

    def get_logical_dhcp_server(self, os_name, os_uuid):
        """
        Get the logical dhcp server based on the name and uuid provided.

        The name of the logical dhcp server should follow
            <os_network_name>_<first 5 os uuid>...<last 5 os uuid>
        Return logical dhcp server if found, otherwise return None
        """
        if not os_name or not os_uuid:
            LOG.error(_LE("Name and uuid of OpenStack L2 network need to be "
                          "present in order to query backend logical dhcp "
                          "server!"))
            return None
        nsx_name = os_name + "_" + os_uuid[:5] + "..." + os_uuid[-5:]
        dhcp_servers = self.get_logical_dhcp_servers()
        return self.get_nsx_resource_by_name(dhcp_servers, nsx_name)

    def get_dhcp_server_static_bindings(self, dhcp_server):
        """
        Get all DHCP static bindings of a logical DHCP server
        """
        uri = "/dhcp/servers/%s/static-bindings" % dhcp_server
        response = self.get(endpoint=uri)
        return response.json()['results']
