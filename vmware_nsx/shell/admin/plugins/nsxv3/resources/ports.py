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

from oslo_log import log as logging

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.dvs import dvs
from vmware_nsx.plugins.nsx_v3 import plugin
from vmware_nsx.plugins.nsx_v3 import utils as plugin_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as v3_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3 import resources
from vmware_nsxlib.v3 import security

from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import portsecurity_db
from neutron_lib.callbacks import registry
from neutron_lib import constants as const
from neutron_lib import context as neutron_context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)


class PortsPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  portsecurity_db.PortSecurityDbMixin,
                  addr_pair_db.AllowedAddressPairsMixin):
    def __enter__(self):
        directory.add_plugin(plugin_constants.CORE, self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        directory.add_plugin(plugin_constants.CORE, None)


def get_network_nsx_id(session, neutron_id):
    # get the nsx switch id from the DB mapping
    mappings = nsx_db.get_nsx_switch_ids(session, neutron_id)
    if not mappings or len(mappings) == 0:
        LOG.debug("Unable to find NSX mappings for neutron "
                  "network %s.", neutron_id)
        # fallback in case we didn't find the id in the db mapping
        # This should not happen, but added here in case the network was
        # created before this code was added.
        return neutron_id
    else:
        return mappings[0]


@admin_utils.output_header
def list_missing_ports(resource, event, trigger, **kwargs):
    """List neutron ports that are missing the NSX backend port
    And ports with wrong switch profiles or bindings
    """
    admin_cxt = neutron_context.get_admin_context()
    filters = v3_utils.get_plugin_filters(admin_cxt)
    nsxlib = v3_utils.get_connected_nsxlib()
    with v3_utils.NsxV3PluginWrapper() as plugin:
        problems = plugin_utils.get_mismatch_logical_ports(
            admin_cxt, nsxlib, plugin, filters)

    if len(problems) > 0:
        title = ("Found internal ports misconfiguration on the "
                 "NSX manager:")
        LOG.info(formatters.output_formatter(
            title, problems,
            ['neutron_id', 'nsx_id', 'error']))
    else:
        LOG.info("All internal ports verified on the NSX manager")


def get_vm_network_device(vm_mng, vm_moref, mac_address):
    """Return the network device with MAC 'mac_address'.

    This code was inspired by Nova vif.get_network_device
    """
    hardware_devices = vm_mng.get_vm_interfaces_info(vm_moref)
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice
    for device in hardware_devices:
        if hasattr(device, 'macAddress'):
            if device.macAddress == mac_address:
                return device


def migrate_compute_ports_vms(resource, event, trigger, **kwargs):
    """Update the VMs ports on the backend after migrating nsx-v -> nsx-v3

    After using api_replay to migrate the neutron data from NSX-V to NSX-T
    we need to update the VM ports to use OpaqueNetwork instead of
    DistributedVirtualPortgroup
    """
    # Connect to the DVS manager, using the configuration parameters
    try:
        vm_mng = dvs.VMManager()
    except Exception as e:
        LOG.error("Cannot connect to the DVS: Please update the [dvs] "
                  "section in the nsx.ini file: %s", e)
        return

    port_filters = {}
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        project = properties.get('project-id')
        if project:
            port_filters['project_id'] = [project]
        net_name = properties.get('net-name', 'VM Network')
        LOG.info("Common network name for migration %s", net_name)
        host_moref = properties.get('host-moref')
        # TODO(garyk): We can explore the option of passing the cluster
        # moref then this will remove the need for the host-moref and the
        # resource pool moref.
        respool_moref = properties.get('respool-moref')
        datastore_moref = properties.get('datastore-moref')
        if not host_moref:
            LOG.error("Unable to migrate with no host")
            return

    # Go over all the ports from the plugin
    admin_cxt = neutron_context.get_admin_context()
    with PortsPlugin() as plugin:
        neutron_ports = plugin.get_ports(admin_cxt, filters=port_filters)

    for port in neutron_ports:
        # skip non compute ports
        if (not port.get('device_owner').startswith(
            const.DEVICE_OWNER_COMPUTE_PREFIX)):
            continue
        device_id = port.get('device_id')

        # get the vm moref & spec from the DVS
        vm_moref = vm_mng.get_vm_moref_obj(device_id)
        vm_spec = vm_mng.get_vm_spec(vm_moref)
        if not vm_spec:
            LOG.error("Failed to get the spec of vm %s", device_id)
            continue

        # Go over the VM interfaces and check if it should be updated
        update_spec = False
        for prop in vm_spec.propSet:
            if (prop.name == 'network' and
                hasattr(prop.val, 'ManagedObjectReference')):
                for net in prop.val.ManagedObjectReference:
                    if (net._type == 'DistributedVirtualPortgroup' or
                        net._type == 'Network'):
                        update_spec = True

        if not update_spec:
            LOG.info("No need to update the spec of vm %s", device_id)
            continue

        device = get_vm_network_device(vm_mng, vm_moref, port['mac_address'])
        if device is None:
            LOG.warning("No device with MAC address %s exists on the VM",
                        port['mac_address'])
            continue

        # Update interface to be common network
        devices = [vm_mng.update_vm_network(device, name=net_name)]
        LOG.info("Update instance %s to common network", device_id)
        vm_mng.update_vm_interface(vm_moref, devices=devices)
        LOG.info("Migrate instance %s to host %s", device_id, host_moref)
        vm_mng.relocate_vm(vm_moref, host_moref=host_moref,
                           datastore_moref=datastore_moref,
                           respool_moref=respool_moref)
        LOG.info("Update instance %s to opaque network", device_id)
        device = get_vm_network_device(vm_mng, vm_moref, port['mac_address'])
        vif_info = {'nsx_id': get_network_nsx_id(admin_cxt.session,
                                                 port['network_id']),
                    'iface_id': port['id']}
        devices = [vm_mng.update_vm_opaque_spec(vif_info, device)]
        vm_mng.update_vm_interface(vm_moref, devices=devices)
        LOG.info("Instance %s successfully migrated!", device_id)


def migrate_exclude_ports(resource, event, trigger, **kwargs):
    _nsx_client = v3_utils.get_nsxv3_client()

    nsxlib = v3_utils.get_connected_nsxlib()
    version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_2_0_0(version):
        LOG.info("Migration only supported from 2.0 onwards")
        LOG.info("Version is %s", version)
        return
    admin_cxt = neutron_context.get_admin_context()
    plugin = PortsPlugin()
    _port_client = resources.LogicalPort(_nsx_client)
    exclude_list = nsxlib.firewall_section.get_excludelist()
    for member in exclude_list['members']:
        if member['target_type'] == 'LogicalPort':
            port_id = member['target_id']
            # Get port
            try:
                nsx_port = _port_client.get(port_id)
            except nsx_exc.ResourceNotFound:
                LOG.info("Port %s not found", port_id)
                continue
            # Validate its a neutron port
            is_neutron_port = False
            for tag in nsx_port.get('tags', []):
                if tag['scope'] == 'os-neutron-port-id':
                    is_neutron_port = True
                    neutron_port_id = tag['tag']
                    break
            if not is_neutron_port:
                LOG.info("Port %s is not a neutron port", port_id)
                continue
            # Check if this port exists in the DB
            try:
                plugin.get_port(admin_cxt, neutron_port_id)
            except Exception:
                LOG.info("Port %s is not defined in DB", neutron_port_id)
                continue
            # Update tag for the port
            tags_update = [{'scope': security.PORT_SG_SCOPE,
                            'tag': nsxlib_consts.EXCLUDE_PORT}]
            _port_client.update(port_id, None,
                                tags_update=tags_update)
            # Remove port from the exclude list
            nsxlib.firewall_section.remove_member_from_fw_exclude_list(
                port_id, nsxlib_consts.TARGET_TYPE_LOGICAL_PORT)
            LOG.info("Port %s successfully updated", port_id)


def tag_default_ports(resource, event, trigger, **kwargs):
    nsxlib = v3_utils.get_connected_nsxlib()
    admin_cxt = neutron_context.get_admin_context()
    filters = v3_utils.get_plugin_filters(admin_cxt)

    # the plugin creation below will create the NS group and update the default
    # OS section to have the correct applied to group
    with v3_utils.NsxV3PluginWrapper() as _plugin:
        neutron_ports = _plugin.get_ports(admin_cxt, filters=filters)
        for port in neutron_ports:
            neutron_id = port['id']
            # get the network nsx id from the mapping table
            nsx_id = plugin_utils.get_port_nsx_id(admin_cxt.session,
                                                  neutron_id)
            if not nsx_id:
                continue
            device_owner = port['device_owner']
            if (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF or
                device_owner == const.DEVICE_OWNER_DHCP):
                continue
            ps = _plugin._get_port_security_binding(admin_cxt,
                                                    neutron_id)
            if not ps:
                continue
            try:
                nsx_port = nsxlib.logical_port.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                continue
            tags_update = nsx_port['tags']
            tags_update += [{'scope': security.PORT_SG_SCOPE,
                             'tag': plugin.NSX_V3_DEFAULT_SECTION}]
            nsxlib.logical_port.update(nsx_id, None,
                                       tags_update=tags_update)


registry.subscribe(list_missing_ports,
                   constants.PORTS,
                   shell.Operations.LIST_MISMATCHES.value)

registry.subscribe(migrate_compute_ports_vms,
                   constants.PORTS,
                   shell.Operations.NSX_MIGRATE_V_V3.value)

registry.subscribe(migrate_exclude_ports,
                   constants.PORTS,
                   shell.Operations.NSX_MIGRATE_EXCLUDE_PORTS.value)


registry.subscribe(tag_default_ports,
                   constants.PORTS,
                   shell.Operations.NSX_TAG_DEFAULT.value)
