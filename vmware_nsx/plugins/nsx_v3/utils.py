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
import os
import random

from oslo_config import cfg
from oslo_context import context as context_utils
from oslo_log import log as logging
from oslo_utils import fileutils
from sqlalchemy.orm import exc

from neutron.db.models import securitygroup
from neutron import version as n_version
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib import constants as const
from neutron_lib import context as q_context

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_models
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsx.services.qos.common import utils as qos_utils
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy

NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'

NSX_V3_PSEC_PROFILE_NAME = 'neutron_port_spoof_guard_profile'
NSX_V3_DHCP_PROFILE_NAME = 'neutron_port_dhcp_profile'

PORT_ERROR_TYPE_MISSING = "Missing port"
PORT_ERROR_TYPE_PROFILE = "Wrong switching profiles"
PORT_ERROR_TYPE_BINDINGS = "Wrong address binding"

LOG = logging.getLogger(__name__)


class DbCertProvider(client_cert.ClientCertProvider):
    """Write cert data from DB to file and delete after use

       New provider object with random filename is created for each request.
       This is not most efficient, but the safest way to avoid race conditions,
       since backend connections can occur both before and after neutron
       fork, and several concurrent requests can occupy the same thread.
       Note that new cert filename for each request does not result in new
       connection for each request (at least for now..)
    """
    EXPIRATION_ALERT_DAYS = 30          # days prior to expiration

    def __init__(self):
        super(DbCertProvider, self).__init__(None)
        random.seed()
        self._filename = '/tmp/.' + str(random.randint(1, 10000000))

    def _check_expiration(self, expires_in_days):
        if expires_in_days > self.EXPIRATION_ALERT_DAYS:
            return

        if expires_in_days < 0:
            LOG.error("Client certificate has expired %d days ago.",
                      expires_in_days * -1)
        else:
            LOG.warning("Client certificate expires in %d days. "
                        "Once expired, service will become unavailable.",
                        expires_in_days)

    def __enter__(self):
        try:
            context = q_context.get_admin_context()
            db_storage_driver = cert_utils.DbCertificateStorageDriver(
                context)
            with client_cert.ClientCertificateManager(
                cert_utils.NSX_OPENSTACK_IDENTITY,
                None,
                db_storage_driver) as cert_manager:
                if not cert_manager.exists():
                    msg = _("Unable to load from nsx-db")
                    raise nsx_exc.ClientCertificateException(err_msg=msg)

                filename = self._filename
                if not os.path.exists(os.path.dirname(filename)):
                    if len(os.path.dirname(filename)) > 0:
                        fileutils.ensure_tree(os.path.dirname(filename))
                cert_manager.export_pem(filename)

                expires_in_days = cert_manager.expires_in_days()
                self._check_expiration(expires_in_days)
        except Exception as e:
            self._on_exit()
            raise e

        return self

    def _on_exit(self):
        if os.path.isfile(self._filename):
            os.remove(self._filename)

        self._filename = None

    def __exit__(self, type, value, traceback):
        self._on_exit()

    def filename(self):
        return self._filename


def get_client_cert_provider(conf_path=cfg.CONF.nsx_v3):
    if not conf_path.nsx_use_client_auth:
        return None

    if conf_path.nsx_client_cert_storage.lower() == 'none':
        # Admin is responsible for providing cert file, the plugin
        # should not touch it
        return client_cert.ClientCertProvider(
                conf_path.nsx_client_cert_file)

    if conf_path.nsx_client_cert_storage.lower() == 'nsx-db':
        # Cert data is stored in DB, and written to file system only
        # when new connection is opened, and deleted immediately after.
        return DbCertProvider


def get_nsxlib_wrapper(nsx_username=None, nsx_password=None, basic_auth=False,
                       plugin_conf=None, allow_overwrite_header=False):
    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider()

    if not plugin_conf:
        plugin_conf = cfg.CONF.nsx_v3
    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or plugin_conf.nsx_api_user,
        password=nsx_password or plugin_conf.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=plugin_conf.http_retries,
        insecure=plugin_conf.insecure,
        ca_file=plugin_conf.ca_file,
        concurrent_connections=plugin_conf.concurrent_connections,
        http_timeout=plugin_conf.http_timeout,
        http_read_timeout=plugin_conf.http_read_timeout,
        conn_idle_timeout=plugin_conf.conn_idle_timeout,
        http_provider=None,
        max_attempts=plugin_conf.retries,
        nsx_api_managers=plugin_conf.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain,
        allow_overwrite_header=allow_overwrite_header)
    return v3.NsxLib(nsxlib_config)


def get_nsxpolicy_wrapper(nsx_username=None, nsx_password=None,
                          basic_auth=False):
    #TODO(asarfaty) move to a different file? (under common_v3)
    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider(
            conf_path=cfg.CONF.nsx_p)

    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or cfg.CONF.nsx_p.nsx_api_user,
        password=nsx_password or cfg.CONF.nsx_p.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=cfg.CONF.nsx_p.http_retries,
        insecure=cfg.CONF.nsx_p.insecure,
        ca_file=cfg.CONF.nsx_p.ca_file,
        concurrent_connections=cfg.CONF.nsx_p.concurrent_connections,
        http_timeout=cfg.CONF.nsx_p.http_timeout,
        http_read_timeout=cfg.CONF.nsx_p.http_read_timeout,
        conn_idle_timeout=cfg.CONF.nsx_p.conn_idle_timeout,
        http_provider=None,
        max_attempts=cfg.CONF.nsx_p.retries,
        nsx_api_managers=cfg.CONF.nsx_p.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        allow_passthrough=cfg.CONF.nsx_p.allow_passthrough,
        realization_max_attempts=cfg.CONF.nsx_p.realization_max_attempts,
        realization_wait_sec=cfg.CONF.nsx_p.realization_wait_sec)
    return policy.NsxPolicyLib(nsxlib_config)


def get_orphaned_dhcp_servers(context, plugin, nsxlib, dhcp_profile_uuid=None):
    # An orphaned DHCP server means the associated neutron network
    # does not exist or has no DHCP-enabled subnet.

    orphaned_servers = []
    server_net_pairs = []

    # Find matching DHCP servers (for a given dhcp_profile_uuid).
    response = nsxlib.dhcp_server.list()
    for dhcp_server in response['results']:
        if (dhcp_profile_uuid and
            dhcp_server['dhcp_profile_id'] != dhcp_profile_uuid):
            continue
        found = False
        neutron_obj = False
        for tag in dhcp_server.get('tags', []):
            if tag['scope'] == 'os-neutron-net-id':
                dhcp_server['neutron_net_id'] = tag['tag']
                server_net_pairs.append((dhcp_server, tag['tag']))
                found = True
            if tag['scope'] == 'os-api-version':
                neutron_obj = True
        if not found and neutron_obj:
            # The associated neutron network is not defined.
            dhcp_server['neutron_net_id'] = None
            orphaned_servers.append(dhcp_server)

    # Check if there is DHCP-enabled subnet in each network.
    for dhcp_server, net_id in server_net_pairs:
        try:
            network = plugin.get_network(context, net_id)
        except Exception:
            # The associated neutron network is not found in DB.
            orphaned_servers.append(dhcp_server)
            continue
        dhcp_enabled = False
        for subnet_id in network['subnets']:
            subnet = plugin.get_subnet(context, subnet_id)
            if subnet['enable_dhcp']:
                dhcp_enabled = True
                break
        if not dhcp_enabled:
            orphaned_servers.append(dhcp_server)

    return orphaned_servers


def delete_orphaned_dhcp_server(context, nsxlib, server):
    # Delete an orphaned DHCP server:
    # (1) delete the attached logical DHCP port,
    # (2) delete the logical DHCP server,
    # (3) clean corresponding neutron DB entry.
    # Return True if it was deleted, or false + error if not
    try:
        response = nsxlib.logical_port.get_by_attachment('DHCP_SERVICE',
                                                         server['id'])
        if response and response['result_count'] > 0:
            nsxlib.logical_port.delete(response['results'][0]['id'])
        nsxlib.dhcp_server.delete(server['id'])
        net_id = server.get('neutron_net_id')
        if net_id:
            # Delete neutron_net_id -> dhcp_service_id mapping from the DB.
            nsx_db.delete_neutron_nsx_service_binding(
                context.session, net_id,
                nsx_constants.SERVICE_DHCP)
        return True, None
    except Exception as e:
        return False, e


def get_orphaned_networks(context, nsxlib):
    nsx_switches = nsxlib.logical_switch.list()['results']
    missing_networks = []
    for nsx_switch in nsx_switches:
        # check if it exists in the neutron DB
        net_ids = nsx_db.get_net_ids(context.session, nsx_switch['id'])
        if not net_ids:
            # Skip non-neutron networks, by tags
            neutron_net = False
            for tag in nsx_switch.get('tags', []):
                if tag.get('scope') == 'os-neutron-net-id':
                    neutron_net = True
                    nsx_switch['neutron_net_id'] = tag['tag']
                    break
            if neutron_net:
                missing_networks.append(nsx_switch)
    return missing_networks


def get_orphaned_routers(context, nsxlib):
    nsx_routers = nsxlib.logical_router.list()['results']
    missing_routers = []
    for nsx_router in nsx_routers:
        # check if it exists in the neutron DB
        neutron_id = nsx_db.get_neutron_from_nsx_router_id(context.session,
                                                           nsx_router['id'])
        if not neutron_id:
            # Skip non-neutron routers, by tags
            for tag in nsx_router.get('tags', []):
                if tag.get('scope') == 'os-neutron-router-id':
                    nsx_router['neutron_router_id'] = tag['tag']
                    missing_routers.append(nsx_router)
                    break
    return missing_routers


def delete_orphaned_router(nsxlib, nsx_id):
    # Delete an orphaned logical router from the NSX:
    # (1) delete the attached ports,
    # (2) delete the logical router
    # Return True if it was deleted, or false + error if not
    try:
        # first delete its ports
        ports = nsxlib.logical_router_port.get_by_router_id(nsx_id)
        for port in ports:
            nsxlib.logical_router_port.delete(port['id'])
        nsxlib.logical_router.delete(nsx_id)
    except Exception as e:
        return False, e
    else:
        return True, None


def get_security_groups_mappings(context):
    q = context.session.query(
        securitygroup.SecurityGroup.name,
        securitygroup.SecurityGroup.id,
        nsx_models.NeutronNsxFirewallSectionMapping.nsx_id,
        nsx_models.NeutronNsxSecurityGroupMapping.nsx_id).join(
            nsx_models.NeutronNsxFirewallSectionMapping,
            nsx_models.NeutronNsxSecurityGroupMapping).all()
    sg_mappings = [{'name': mapp[0],
                    'id': mapp[1],
                    'section-id': mapp[2],
                    'nsx-securitygroup-id': mapp[3]}
                   for mapp in q]
    return sg_mappings


def get_orphaned_firewall_sections(context, nsxlib):
    fw_sections = nsxlib.firewall_section.list()
    sg_mappings = get_security_groups_mappings(context)
    orphaned_sections = []
    for fw_section in fw_sections:
        for sg_db in sg_mappings:
            if fw_section['id'] == sg_db['section-id']:
                break
        else:
            # Skip non-neutron sections, by tags
            neutron_obj = False
            for tag in fw_section.get('tags', []):
                if tag['scope'] == 'os-api-version':
                    neutron_obj = True
                if tag.get('scope') == 'os-neutron-secgr-id':
                    fw_section['neutron_sg_id'] = tag['tag']
            if neutron_obj:
                orphaned_sections.append(fw_section)
    return orphaned_sections


def get_dhcp_profile_id(nsxlib):
    profiles = nsxlib.switching_profile.find_by_display_name(
        NSX_V3_DHCP_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning("Could not find DHCP profile on backend")


def get_spoofguard_profile_id(nsxlib):
    profiles = nsxlib.switching_profile.find_by_display_name(
        NSX_V3_PSEC_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning("Could not find Spoof Guard profile on backend")


def add_profile_mismatch(problems, neutron_id, nsx_id, prf_id, title):
    msg = ('Wrong %(title)s profile %(prf_id)s') % {'title': title,
                                                    'prf_id': prf_id}
    problems.append({'neutron_id': neutron_id,
                     'nsx_id': nsx_id,
                     'error': msg,
                     'error_type': PORT_ERROR_TYPE_PROFILE})


def get_port_nsx_id(session, neutron_id):
    # get the nsx port id from the DB mapping
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_port_id']
    except exc.NoResultFound:
        pass


def get_mismatch_logical_ports(context, nsxlib, plugin, get_filters=None):
    neutron_ports = plugin.get_ports(context, filters=get_filters)

    # get pre-defined profile ids
    dhcp_profile_id = get_dhcp_profile_id(nsxlib)
    dhcp_profile_key = (
        core_resources.SwitchingProfileTypes.SWITCH_SECURITY)
    spoofguard_profile_id = get_spoofguard_profile_id(nsxlib)
    spoofguard_profile_key = (
        core_resources.SwitchingProfileTypes.SPOOF_GUARD)
    qos_profile_key = core_resources.SwitchingProfileTypes.QOS

    problems = []
    for port in neutron_ports:
        neutron_id = port['id']
        # get the network nsx id from the mapping table
        nsx_id = get_port_nsx_id(context.session, neutron_id)
        if not nsx_id:
            # skip external ports
            pass
        else:
            try:
                nsx_port = nsxlib.logical_port.get(nsx_id)
            except nsxlib_exc.ResourceNotFound:
                problems.append({'neutron_id': neutron_id,
                                 'nsx_id': nsx_id,
                                 'error': 'Missing from backend',
                                 'error_type': PORT_ERROR_TYPE_MISSING})
                continue

            # Port found on backend!
            # Check that it has all the expected switch profiles.
            # create a dictionary of the current profiles:
            profiles_dict = {}
            for prf in nsx_port['switching_profile_ids']:
                profiles_dict[prf['key']] = prf['value']

            # DHCP port: neutron dhcp profile should be attached
            # to logical ports created for neutron DHCP but not
            # for native DHCP.
            if (port.get('device_owner') == const.DEVICE_OWNER_DHCP and
                not cfg.CONF.nsx_v3.native_dhcp_metadata):
                prf_id = profiles_dict[dhcp_profile_key]
                if prf_id != dhcp_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "DHCP security")

            # Port with QoS policy: a matching profile should be attached
            qos_policy_id = qos_utils.get_port_policy_id(context,
                                                         neutron_id)
            if qos_policy_id:
                qos_profile_id = nsx_db.get_switch_profile_by_qos_policy(
                    context.session, qos_policy_id)
                prf_id = profiles_dict[qos_profile_key]
                if prf_id != qos_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "QoS")

            # Port with security & fixed ips/address pairs:
            # neutron spoofguard profile should be attached
            port_sec, has_ip = plugin._determine_port_security_and_has_ip(
                context, port)
            addr_pair = port.get(addr_apidef.ADDRESS_PAIRS)
            if port_sec and (has_ip or addr_pair):
                prf_id = profiles_dict[spoofguard_profile_key]
                if prf_id != spoofguard_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "Spoof Guard")

            # Check the address bindings
            if port_sec:
                nsx_address_bindings = nsx_port.get('address_bindings', [])
                nsx_ips = [x['ip_address'] for x in nsx_address_bindings]
                nsx_macs = [x['mac_address'] for x in nsx_address_bindings]
                neutron_ips = [x['ip_address']
                               for x in port.get('fixed_ips', [])]
                neutron_mac = port['mac_address']
                different_macs = [mac for mac in nsx_macs
                                  if mac != neutron_mac]
                if (len(nsx_ips) != len(neutron_ips) or
                    set(nsx_ips) != set(neutron_ips)):
                    problems.append({'neutron_id': neutron_id,
                                     'nsx_id': nsx_id,
                                     'port': port,
                                     'error': 'Different IP address bindings',
                                     'error_type': PORT_ERROR_TYPE_BINDINGS})
                elif different_macs:
                    problems.append({'neutron_id': neutron_id,
                                     'nsx_id': nsx_id,
                                     'port': port,
                                     'error': 'Different MAC address bindings',
                                     'error_type': PORT_ERROR_TYPE_BINDINGS})
    return problems


def inject_headers():
    ctx = context_utils.get_current()
    if ctx:
        ctx_dict = ctx.to_dict()
        return {'X-NSX-EUSER': ctx_dict.get('user_identity'),
                'X-NSX-EREQID': ctx_dict.get('request_id')}
    return {}


def inject_requestid_header():
    ctx = context_utils.get_current()
    if ctx:
        return {'X-NSX-EREQID': ctx.__dict__.get('request_id')}
    return {}
