# Copyright 2015 VMware Inc
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
import optparse
import requests

from oslo_serialization import jsonutils


requests.packages.urllib3.disable_warnings()


class NSXClient(object):
    """Base NSX REST client"""
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
        self.api_version = NSXClient.API_VERSION

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
        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            p['attachment'] = None
            endpoint = "/logical-ports/%s" % p['id']
            response = self.put(endpoint=endpoint, body=p)
            if response.status_code != requests.codes.ok:
                print("ERROR: Failed to update lport %s" % p['id'])

    def cleanup_os_logical_ports(self):
        """
        Delete all logical ports created by OpenStack
        """
        lports = self.get_logical_ports()
        os_lports = self.get_os_resources(lports)
        print("Number of OS Logical Ports to be deleted: %s" % len(os_lports))
        # logical port vif detachment
        self.update_logical_port_attachment(os_lports)
        for p in os_lports:
            endpoint = '/logical-ports/%s' % p['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted logical port %s" % p['id'])
            else:
                print("ERROR: Failed to delete lport %s, response code %s" %
                      (p['id'], response.status_code))

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-api-version' in tag.values()]
        return os_resources

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        response = self.get(endpoint="/logical-switches")
        return response.json()['results']

    def get_os_logical_switches(self):
        """
        Retrieve all logical switches created from OpenStack
        """
        lswitches = self.get_logical_switches()
        return self.get_os_resources(lswitches)

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] is ls_id]

    def cleanup_os_logical_switches(self):
        """
        Delete all logical switches created from OpenStack
        """
        lswitches = self.get_os_logical_switches()
        print("Number of OS Logical Switches to be deleted: %s" %
              len(lswitches))
        for ls in lswitches:
            endpoint = '/logical-switches/%s' % ls['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted logical switch %s-%s" %
                      (ls['display_name'], ls['id']))
            else:
                print("Failed to delete lswitch %s-%s, and response is %s" %
                      (ls['display_name'], ls['id'], response.status_code))

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        response = self.get(endpoint="/firewall/sections")
        return response.json()['results']

    def get_os_firewall_sections(self):
        """
        Retrieve all firewall sections created from OpenStack
        """
        fw_sections = self.get_firewall_sections()
        return self.get_os_resources(fw_sections)

    def get_firewall_section_rules(self, fw_section):
        """
        Retrieve all fw rules for a given fw section
        """
        endpoint = "/firewall/sections/%s/rules" % fw_section['id']
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def cleanup_firewall_section_rules(self, fw_section):
        """
        Cleanup all firewall rules for a given fw section
        """
        fw_rules = self.get_firewall_section_rules(fw_section)
        for rule in fw_rules:
            endpoint = "/firewall/sections/%s/rules/%s" % (fw_section['id'],
                                                           rule['id'])
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted fw rule %s in fw section %s" %
                      (rule['display_name'], fw_section['display_name']))
            else:
                print("Failed to delete fw rule %s in fw section %s" %
                      (rule['display_name'], fw_section['display_name']))

    def cleanup_os_firewall_sections(self):
        """
        Cleanup all firewall sections created from OpenStack
        """
        fw_sections = self.get_os_firewall_sections()
        print("Number of OS Firewall Sections to be deleted: %s" %
              len(fw_sections))
        for fw in fw_sections:
            self.cleanup_firewall_section_rules(fw)
            endpoint = "/firewall/sections/%s" % fw['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted firewall section %s" %
                      fw['display_name'])
            else:
                print("Failed to delete firewall section %s" %
                      fw['display_name'])

    def get_ns_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        response = self.get(endpoint="/ns-groups")
        ns_groups = response.json()['results']
        return self.get_os_resources(ns_groups)

    def cleanup_os_ns_groups(self):
        """
        Cleanup all NSGroups created from OpenStack plugin
        """
        ns_groups = self.get_ns_groups()
        print("Number of OS NSGroups to be deleted: %s" % len(ns_groups))
        for nsg in ns_groups:
            endpoint = "/ns-groups/%s?force=true" % nsg['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted NSGroup: %s" % nsg['display_name'])
            else:
                print("Failed to delete NSGroup: %s" % nsg['display_name'])

    def get_switching_profiles(self):
        """
        Retrieve all Switching Profiles on NSX backend
        """
        response = self.get(endpoint="/switching-profiles")
        return response.json()['results']

    def get_os_switching_profiles(self):
        """
        Retrieve all Switching Profiles created from OpenStack
        """
        sw_profiles = self.get_switching_profiles()
        return self.get_os_resources(sw_profiles)

    def cleanup_os_switching_profiles(self):
        """
        Cleanup all Switching Profiles created from OpenStack plugin
        """
        sw_profiles = self.get_os_switching_profiles()
        print("Number of OS SwitchingProfiles to be deleted: %s" %
              len(sw_profiles))
        for swp in sw_profiles:
            endpoint = "/switching-profiles/%s" % swp['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted Switching Profile: %s" %
                      swp['display_name'])
            else:
                print("Failed to delete Switching Profile: %s" %
                      swp['display_name'])

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

    def get_os_logical_routers(self):
        """
        Retrive all logical routers created from Neutron NSXv3 plugin
        """
        lrouters = self.get_logical_routers()
        return self.get_os_resources(lrouters)

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        endpoint = "/logical-router-ports?logical_router_id=%s" % lrouter['id']
        response = self.get(endpoint=endpoint)
        return response.json()['results']

    def get_os_logical_router_ports(self, lrouter):
        """
        Retrieve all logical router ports created from Neutron NSXv3 plugin
        """
        lports = self.get_logical_router_ports(lrouter)
        return self.get_os_resources(lports)

    def cleanup_logical_router_ports(self, lrouter):
        """
        Cleanup all logical ports on a logical router
        """
        lports = self.get_os_logical_router_ports(lrouter)
        for lp in lports:
            endpoint = "/logical-router-ports/%s" % lp['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted logical router port %s-%s" %
                      (lp['display_name'], lp['id']))
            else:
                print("Failed to delete lr port %s-%s, and response is %s" %
                      (lp['display_name'], lp['id']))

    def cleanup_os_logical_routers(self):
        """
        Delete all logical routers created from OpenStack
        To delete a logical router, we need to delete all logical
        ports on the router first.
        """
        lrouters = self.get_os_logical_routers()
        print("Number of OS Logical Routers to be deleted: %s" %
              len(lrouters))
        for lr in lrouters:
            self.cleanup_logical_router_ports(lr)
            endpoint = "/logical-routers/%s" % lr['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted logical router %s-%s" %
                      (lr['display_name'], lr['id']))
            else:
                print("Failed to delete lrouter %s-%s, and response is %s" %
                      (lr['display_name'], lr['id']))

    def cleanup_os_tier0_logical_ports(self):
        """
        Delete all TIER0 logical router ports created from OpenStack
        """
        tier0_routers = self.get_logical_routers(tier='TIER0')
        for lr in tier0_routers:
            self.cleanup_logical_router_ports(lr)

    def get_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers on NSX backend
        """
        response = self.get(endpoint="/dhcp/servers")
        return response.json()['results']

    def get_os_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers created from OpenStack
        """
        dhcp_servers = self.get_logical_dhcp_servers()
        return self.get_os_resources(dhcp_servers)

    def cleanup_os_logical_dhcp_servers(self):
        """
        Cleanup all logical DHCP servers created from OpenStack plugin
        """
        dhcp_servers = self.get_os_logical_dhcp_servers()
        print("Number of OS Logical DHCP Servers to be deleted: %s" %
              len(dhcp_servers))
        for server in dhcp_servers:
            endpoint = "/dhcp/servers/%s" % server['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == requests.codes.ok:
                print("Successfully deleted logical DHCP server: %s" %
                      server['display_name'])
            else:
                print("Failed to delete logical DHCP server: %s" %
                      server['display_name'])

    def cleanup_all(self):
        """
        Cleanup steps:
            1. Cleanup firewall sections
            2. Cleanup NSGroups
            3. Cleanup logical router ports
            4. Cleanup logical routers
            5. Cleanup logical switch ports
            6. Cleanup logical switches
            7. Cleanup switching profiles
        """
        self.cleanup_os_firewall_sections()
        self.cleanup_os_ns_groups()
        self.cleanup_os_logical_routers()
        self.cleanup_os_tier0_logical_ports()
        self.cleanup_os_logical_ports()
        self.cleanup_os_logical_switches()
        self.cleanup_os_logical_dhcp_servers()
        self.cleanup_os_switching_profiles()


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.mgr_ip, options.username,
                           options.password)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
