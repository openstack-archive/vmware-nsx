# Copyright 2016  VMware, Inc.
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


class NsxLibConfig(object):
    """Class holding all the configuration parameters used by the nsxlib code.

    :param nsx_api_managers: List of IP addresses of the NSX managers.
                             Each IP address should be of the form:
                             [<scheme>://]<ip_adress>[:<port>]
                             If scheme is not provided https is used.
                             If port is not provided port 80 is used for http
                             and port 443 for https.
    :param username: User name for the NSX manager
    :param password: Password for the NSX manager
    :param insecure: If true, the NSX Manager server certificate is not
                     verified. If false the CA bundle specified via "ca_file"
                     will be used or if unsest the default system root CAs
                     will be used.
    :param ca_file: Specify a CA bundle file to use in verifying the NSX
                    Manager server certificate. This option is ignored if
                    "insecure" is set to True. If "insecure" is set to
                    False and ca_file is unset, the system root CAs will
                    be used to verify the server certificate.

    :param concurrent_connections: Maximum concurrent connections to each NSX
                                   manager.
    :param retries: Maximum number of times to retry a HTTP connection.
    :param http_timeout: The time in seconds before aborting a HTTP connection
                         to a NSX manager.
    :param http_read_timeout: The time in seconds before aborting a HTTP read
                              response from a NSX manager.
    :param conn_idle_timeout: The amount of time in seconds to wait before
                              ensuring connectivity to the NSX manager if no
                              manager connection has been used.
    :param http_provider: HTTPProvider object, or None.

    :param max_attempts: Maximum number of times to retry API requests upon
                         stale revision errors.

    :param plugin_scope: The default scope for the v3 api-version tag
    :param plugin_tag: The value for the v3 api-version tag
    :param plugin_ver: The version of the plugin used as the 'os-api-version'
                       tag value in the v3 api-version tag
    :param dns_nameservers: List of nameservers to configure for the DHCP
                            binding entries. These will be used if there are
                            no nameservers defined on the subnet.
    :param dns_domain: Domain to use for building the hostnames.
    :param dhcp_profile_uuid: The UUID of the NSX DHCP Profile that will be
                              used to enable native DHCP service.

    """

    def __init__(self,
                 nsx_api_managers=None,
                 username=None,
                 password=None,
                 insecure=True,
                 ca_file=None,
                 concurrent_connections=10,
                 retries=3,
                 http_timeout=10,
                 http_read_timeout=180,
                 conn_idle_timeout=10,
                 http_provider=None,
                 max_attempts=10,
                 plugin_scope=None,
                 plugin_tag=None,
                 plugin_ver=None,
                 dns_nameservers=None,
                 dns_domain='openstacklocal',
                 dhcp_profile_uuid=None):

        self.nsx_api_managers = nsx_api_managers
        self._username = username
        self._password = password
        self._ca_file = ca_file
        self.insecure = insecure
        self.concurrent_connections = concurrent_connections
        self.retries = retries
        self.http_timeout = http_timeout
        self.http_read_timeout = http_read_timeout
        self.conn_idle_timeout = conn_idle_timeout
        self.http_provider = http_provider
        self.max_attempts = max_attempts
        self.plugin_scope = plugin_scope
        self.plugin_tag = plugin_tag
        self.plugin_ver = plugin_ver
        self.dns_nameservers = dns_nameservers or []
        self.dns_domain = dns_domain
        self.dhcp_profile_uuid = dhcp_profile_uuid

    def _attribute_by_index(self, scalar_or_list, index):
        if isinstance(scalar_or_list, list):
            if not len(scalar_or_list):
                return None
            if len(scalar_or_list) > index:
                return scalar_or_list[index]
            # if not long enough - use the first one as default
            return scalar_or_list[0]
        # this is a scalar
        return scalar_or_list

    def username(self, index):
        return self._attribute_by_index(self._username, index)

    def password(self, index):
        return self._attribute_by_index(self._password, index)

    def ca_file(self, index):
        return self._attribute_by_index(self._ca_file, index)
