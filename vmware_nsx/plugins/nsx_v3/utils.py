# Copyright 2016 VMware, Inc.
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
from oslo_config import cfg

from neutron import version as n_version

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config

NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'


def get_nsxlib_wrapper(nsx_username=None, nsx_password=None, basic_auth=False):
    client_cert_file = None
    if not basic_auth and cfg.CONF.nsx_v3.nsx_use_client_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_file = cfg.CONF.nsx_v3.nsx_client_cert_file

    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or cfg.CONF.nsx_v3.nsx_api_user,
        password=nsx_password or cfg.CONF.nsx_v3.nsx_api_password,
        client_cert_file=client_cert_file,
        retries=cfg.CONF.nsx_v3.http_retries,
        insecure=cfg.CONF.nsx_v3.insecure,
        ca_file=cfg.CONF.nsx_v3.ca_file,
        concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
        http_timeout=cfg.CONF.nsx_v3.http_timeout,
        http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
        conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
        http_provider=None,
        max_attempts=cfg.CONF.nsx_v3.retries,
        nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain,
        dhcp_profile_uuid=cfg.CONF.nsx_v3.dhcp_profile)
    return v3.NsxLib(nsxlib_config)
