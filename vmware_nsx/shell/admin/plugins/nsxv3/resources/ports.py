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

from sqlalchemy.orm import exc

from vmware_nsx._i18n import _LI, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_models
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.plugins.nsx_v3 import plugin
from vmware_nsx.services.qos.common import utils as qos_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell import nsxadmin as shell

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db
from neutron.extensions import allowedaddresspairs
from neutron_lib import constants as const

LOG = logging.getLogger(__name__)


class PortsPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  portsecurity_db.PortSecurityDbMixin,
                  addr_pair_db.AllowedAddressPairsMixin):
    pass


def get_port_nsx_id(session, neutron_id):
    # get the nsx port id from the DB mapping
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_port_id']
    except exc.NoResultFound:
        pass


def get_port_and_profile_clients():
    _api_cluster = cluster.NSXClusteredAPI()
    _nsx_client = client.NSX3Client(_api_cluster)
    return (resources.LogicalPort(_nsx_client),
            resources.SwitchingProfile(_nsx_client))


def get_dhcp_profile_id(profile_client):
    profiles = profile_client.find_by_display_name(
        plugin.NSX_V3_DHCP_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning(_LW("Could not find DHCP profile on backend"))


def get_spoofguard_profile_id(profile_client):
    profiles = profile_client.find_by_display_name(
        plugin.NSX_V3_PSEC_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning(_LW("Could not find Spoof Guard profile on backend"))


def add_profile_mismatch(problems, neutron_id, nsx_id, prf_id, title):
    msg = (_LI('Wrong %(title)s profile %(prf_id)s') % {'title': title,
                                                        'prf_id': prf_id})
    problems.append({'neutron_id': neutron_id,
                     'nsx_id': nsx_id,
                     'error': msg})


@admin_utils.output_header
def list_missing_ports(resource, event, trigger, **kwargs):
    """List neutron ports that are missing the NSX backend port
    And ports with wrong switch profiles
    """
    plugin = PortsPlugin()
    admin_cxt = neutron_context.get_admin_context()
    neutron_ports = plugin.get_ports(admin_cxt)
    port_client, profile_client = get_port_and_profile_clients()

    # get pre-defined profile ids
    dhcp_profile_id = get_dhcp_profile_id(profile_client)
    dhcp_profile_key = resources.SwitchingProfileTypes.SWITCH_SECURITY
    spoofguard_profile_id = get_spoofguard_profile_id(profile_client)
    spoofguard_profile_key = resources.SwitchingProfileTypes.SPOOF_GUARD
    qos_profile_key = resources.SwitchingProfileTypes.QOS

    problems = []
    for port in neutron_ports:
        neutron_id = port['id']
        # get the network nsx id from the mapping table
        nsx_id = get_port_nsx_id(admin_cxt.session, neutron_id)
        if not nsx_id:
            # skip external ports
            pass
        else:
            try:
                nsx_port = port_client.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                problems.append({'neutron_id': neutron_id,
                                 'nsx_id': nsx_id,
                                 'error': _LI('Missing from backend')})
                continue

            # Port found on backend!
            # Check that it has all the expected switch profiles.
            # create a dictionary of the current profiles:
            profiles_dict = {}
            for prf in nsx_port['switching_profile_ids']:
                profiles_dict[prf['key']] = prf['value']

            # DHCP port: neutron dhcp profile should be attached
            if port.get('device_owner') == const.DEVICE_OWNER_DHCP:
                prf_id = profiles_dict[dhcp_profile_key]
                if prf_id != dhcp_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "DHCP security")

            # Port with QoS policy: a matching profile should be attached
            qos_policy_id = qos_utils.get_port_policy_id(admin_cxt,
                                                         neutron_id)
            if qos_policy_id:
                qos_profile_id = nsx_db.get_switch_profile_by_qos_policy(
                    admin_cxt.session, qos_policy_id)
                prf_id = profiles_dict[qos_profile_key]
                if prf_id != qos_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "QoS")

            # Port with security & fixed ips/address pairs:
            # neutron spoofguard profile should be attached
            port_sec, has_ip = plugin._determine_port_security_and_has_ip(
                admin_cxt, port)
            addr_pair = port.get(allowedaddresspairs.ADDRESS_PAIRS)
            if port_sec and (has_ip or addr_pair):
                prf_id = profiles_dict[spoofguard_profile_key]
                if prf_id != spoofguard_profile_id:
                    add_profile_mismatch(problems, neutron_id, nsx_id,
                                         prf_id, "Spoof Guard")

    if len(problems) > 0:
        title = _LI("Found internal ports misconfiguration on the "
                    "NSX manager:")
        LOG.info(formatters.output_formatter(
            title, problems,
            ['neutron_id', 'nsx_id', 'error']))
    else:
        LOG.info(_LI("All internal ports verified on the NSX manager"))


registry.subscribe(list_missing_ports,
                   constants.PORTS,
                   shell.Operations.LIST_MISMATCHES.value)
