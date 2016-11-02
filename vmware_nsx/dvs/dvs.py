# Copyright 2014 VMware, Inc.
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

from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_vmware import vim_util

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.dvs import dvs_utils

LOG = logging.getLogger(__name__)
PORTGROUP_PREFIX = 'dvportgroup'
QOS_IN_DIRECTION = 'incomingPackets'
QOS_AGENT_NAME = 'dvfilter-generic-vmware'
API_FIND_ALL_BY_UUID = 'FindAllByUuid'
DSCP_RULE_DESCRIPTION = 'Openstack Dscp Marking Rule'


class DvsManager(object):
    """Management class for dvs related tasks."""

    def __init__(self, dvs_id=None):
        """Initializer.

        A global session with the VC will be established. In addition to this
        the moref of the configured DVS will be learnt. This will be used in
        the operations supported by the manager.

        NOTE: the DVS port group name will be the Neutron network UUID.
        """
        self._session = dvs_utils.dvs_create_session()
        # In the future we may decide to support more than one DVS
        if dvs_id is None:
            self._dvs_moref = self._get_dvs_moref(self._session,
                                                  dvs_utils.dvs_name_get())
        else:
            self._dvs_moref = vim_util.get_moref(dvs_id,
                                              'VmwareDistributedVirtualSwitch')

    def _get_dvs_moref(self, session, dvs_name):
        """Get the moref of the configured DVS."""
        results = session.invoke_api(vim_util,
                                     'get_objects',
                                     session.vim,
                                     'DistributedVirtualSwitch',
                                     100)
        while results:
            for dvs in results.objects:
                for prop in dvs.propSet:
                    if dvs_name == prop.val:
                        vim_util.cancel_retrieval(session.vim, results)
                        return dvs.obj
            results = vim_util.continue_retrieval(session.vim, results)
        raise nsx_exc.DvsNotFound(dvs=dvs_name)

    def _get_port_group_spec(self, net_id, vlan_tag):
        """Gets the port groups spec for net_id and vlan_tag."""
        client_factory = self._session.vim.client.factory
        pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.name = net_id
        pg_spec.type = 'ephemeral'
        config = client_factory.create('ns0:VMwareDVSPortSetting')
        if vlan_tag:
            # Create the spec for the vlan tag
            spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
            vl_spec = client_factory.create(spec_ns)
            vl_spec.vlanId = vlan_tag
            vl_spec.inherited = '0'
            config.vlan = vl_spec
        pg_spec.defaultPortConfig = config
        return pg_spec

    def add_port_group(self, net_id, vlan_tag=None):
        """Add a new port group to the configured DVS."""
        pg_spec = self._get_port_group_spec(net_id, vlan_tag)
        task = self._session.invoke_api(self._session.vim,
                                        'CreateDVPortgroup_Task',
                                        self._dvs_moref,
                                        spec=pg_spec)
        try:
            # NOTE(garyk): cache the returned moref
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to create port group for '
                                  '%(net_id)s with tag %(tag)s.'),
                              {'net_id': net_id, 'tag': vlan_tag})
        LOG.info(_LI("%(net_id)s with tag %(vlan_tag)s created on %(dvs)s."),
                 {'net_id': net_id,
                  'vlan_tag': vlan_tag,
                  'dvs': self._dvs_moref.value})

    def _net_id_to_moref(self, net_id):
        """Gets the moref for the specific neutron network."""
        # NOTE(garyk): return this from a cache if not found then invoke
        # code below.
        port_groups = self._session.invoke_api(vim_util,
                                               'get_object_properties',
                                               self._session.vim,
                                               self._dvs_moref,
                                               ['portgroup'])
        if len(port_groups) and hasattr(port_groups[0], 'propSet'):
            for prop in port_groups[0].propSet:
                for val in prop.val[0]:
                    props = self._session.invoke_api(vim_util,
                                                     'get_object_properties',
                                                     self._session.vim,
                                                     val, ['name'])
                    if len(props) and hasattr(props[0], 'propSet'):
                        for prop in props[0].propSet:
                            # match name or mor id
                            if net_id == prop.val or net_id == val.value:
                                # NOTE(garyk): update cache
                                return val
        raise exceptions.NetworkNotFound(net_id=net_id)

    def _is_vlan_network_by_moref(self, moref):
        """
        This can either be a VXLAN or a VLAN network. The type is determined
        by the prefix of the moref.
        """
        return moref.startswith(PORTGROUP_PREFIX)

    def _copy_port_group_spec(self, orig_spec):
        client_factory = self._session.vim.client.factory
        pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.autoExpand = orig_spec['autoExpand']
        pg_spec.configVersion = orig_spec['configVersion']
        pg_spec.defaultPortConfig = orig_spec['defaultPortConfig']
        pg_spec.name = orig_spec['name']
        pg_spec.numPorts = orig_spec['numPorts']
        pg_spec.policy = orig_spec['policy']
        pg_spec.type = orig_spec['type']
        return pg_spec

    def update_port_group_spec_qos(self, pg_spec, qos_data):
        port_conf = pg_spec.defaultPortConfig
        # Update the in bandwidth shaping policy
        # Note: openstack refers to the directions from the VM point of view,
        # while the NSX refers to the vswitch point of view.
        # so open stack egress is actually inShaping here.
        outPol = port_conf.inShapingPolicy
        if qos_data.bandwidthEnabled:
            outPol.inherited = False
            outPol.enabled.inherited = False
            outPol.enabled.value = True
            outPol.averageBandwidth.inherited = False
            outPol.averageBandwidth.value = qos_data.averageBandwidth
            outPol.peakBandwidth.inherited = False
            outPol.peakBandwidth.value = qos_data.peakBandwidth
            outPol.burstSize.inherited = False
            outPol.burstSize.value = qos_data.burstSize
        else:
            outPol.inherited = True

        # Update the DSCP marking
        if (port_conf.filterPolicy.inherited or
            len(port_conf.filterPolicy.filterConfig) == 0 or
            len(port_conf.filterPolicy.filterConfig[
                0].trafficRuleset.rules) == 0):

            if qos_data.dscpMarkEnabled:
                # create the entire structure
                client_factory = self._session.vim.client.factory
                filter_rule = client_factory.create('ns0:DvsTrafficRule')
                filter_rule.description = DSCP_RULE_DESCRIPTION
                filter_rule.action = client_factory.create(
                    'ns0:DvsUpdateTagNetworkRuleAction')
                filter_rule.action.dscpTag = qos_data.dscpMarkValue
                # mark only incoming packets (openstack egress = nsx ingress)
                filter_rule.direction = QOS_IN_DIRECTION
                # Add IP any->any qualifier
                qualifier = client_factory.create(
                    'ns0:DvsIpNetworkRuleQualifier')
                qualifier.protocol = 0
                qualifier.sourceAddress = None
                qualifier.destinationAddress = None
                filter_rule.qualifier = [qualifier]

                traffic_filter_config = client_factory.create(
                    'ns0:DvsTrafficFilterConfig')
                traffic_filter_config.trafficRuleset.rules = [filter_rule]
                traffic_filter_config.trafficRuleset.enabled = True
                traffic_filter_config.agentName = QOS_AGENT_NAME
                traffic_filter_config.inherited = False

                port_conf.filterPolicy = client_factory.create(
                    'ns0:DvsFilterPolicy')
                port_conf.filterPolicy.filterConfig = [
                    traffic_filter_config]
                port_conf.filterPolicy.inherited = False
        else:
            # The structure was already initialized
            filter_policy = port_conf.filterPolicy
            if qos_data.dscpMarkEnabled:
                # just update the DSCP value
                traffic_filter_config = filter_policy.filterConfig[0]
                filter_rule = traffic_filter_config.trafficRuleset.rules[0]
                filter_rule.action.dscpTag = qos_data.dscpMarkValue
            else:
                # delete the filter policy data
                filter_policy.filterConfig = []

    def _reconfigure_port_group(self, pg_moref, spec_update_calback,
                                spec_update_data):
        # Get the current configuration of the port group
        pg_spec = self._session.invoke_api(vim_util,
                                           'get_object_properties',
                                           self._session.vim,
                                           pg_moref, ['config'])
        if len(pg_spec) == 0 or len(pg_spec[0].propSet[0]) == 0:
            LOG.error(_LE('Failed to get object properties of %s'), pg_moref)
            raise nsx_exc.DvsNotFound(dvs=pg_moref)

        # Convert the extracted config to DVPortgroupConfigSpec
        new_spec = self._copy_port_group_spec(pg_spec[0].propSet[0].val)

        # Update the configuration using the callback & data
        spec_update_calback(new_spec, spec_update_data)

        # Update the port group configuration
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigureDVPortgroup_Task',
                                        pg_moref, spec=new_spec)
        try:
            self._session.wait_for_task(task)
        except Exception:
            LOG.error(_LE('Failed to reconfigure DVPortGroup %s'), pg_moref)
            raise nsx_exc.DvsNotFound(dvs=pg_moref)

    # Update the dvs port groups config for a vxlan/vlan network
    # update the spec using a callback and user data
    def update_port_groups_config(self, net_id, net_moref,
                                  spec_update_calback, spec_update_data):
        is_vlan = self._is_vlan_network_by_moref(net_moref)
        if is_vlan:
            return self._update_net_port_groups_config(net_moref,
                                                       spec_update_calback,
                                                       spec_update_data)
        else:
            return self._update_vxlan_port_groups_config(net_id,
                                                         net_moref,
                                                         spec_update_calback,
                                                         spec_update_data)

    # Update the dvs port groups config for a vxlan network
    # Searching the port groups for a partial match to the network id & moref
    # update the spec using a callback and user data
    def _update_vxlan_port_groups_config(self,
                                         net_id,
                                         net_moref,
                                         spec_update_calback,
                                         spec_update_data):
        port_groups = self._session.invoke_api(vim_util,
                                               'get_object_properties',
                                               self._session.vim,
                                               self._dvs_moref,
                                               ['portgroup'])
        found = False
        if len(port_groups) and hasattr(port_groups[0], 'propSet'):
            for prop in port_groups[0].propSet:
                for pg_moref in prop.val[0]:
                    props = self._session.invoke_api(vim_util,
                                                     'get_object_properties',
                                                     self._session.vim,
                                                     pg_moref, ['name'])
                    if len(props) and hasattr(props[0], 'propSet'):
                        for prop in props[0].propSet:
                            if net_id in prop.val and net_moref in prop.val:
                                found = True
                                self._reconfigure_port_group(
                                    pg_moref,
                                    spec_update_calback,
                                    spec_update_data)

        if not found:
            raise exceptions.NetworkNotFound(net_id=net_id)

    # Update the dvs port groups config for a vlan network
    # Finding the port group using the exact moref of the network
    # update the spec using a callback and user data
    def _update_net_port_groups_config(self,
                                       net_moref,
                                       spec_update_calback,
                                       spec_update_data):
        pg_moref = vim_util.get_moref(net_moref,
                                      "DistributedVirtualPortgroup")
        self._reconfigure_port_group(pg_moref,
                                     spec_update_calback,
                                     spec_update_data)

    def delete_port_group(self, net_id):
        """Delete a specific port group."""
        moref = self._net_id_to_moref(net_id)
        task = self._session.invoke_api(self._session.vim,
                                        'Destroy_Task',
                                        moref)
        try:
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete port group for %s.'),
                              net_id)
        LOG.info(_LI("%(net_id)s delete from %(dvs)s."),
                 {'net_id': net_id,
                  'dvs': self._dvs_moref.value})

    def get_portgroup_info(self, pg_moref):
        """Get portgroup information."""
        # Expand the properties to collect on need basis.
        properties = ['name']
        pg_info = self._session.invoke_api(vim_util,
                                           'get_object_properties_dict',
                                           self._session.vim,
                                           pg_moref, properties)
        return pg_info

    def get_vm_moref_obj(self, instance_uuid):
        """Get reference to the VM.
        The method will make use of FindAllByUuid to get the VM reference.
        This method finds all VM's on the backend that match the
        instance_uuid, more specifically all VM's on the backend that have
        'config_spec.instanceUuid' set to 'instance_uuid'.
        """
        vm_refs = self._session.invoke_api(
            self._session.vim,
            API_FIND_ALL_BY_UUID,
            self._session.vim.service_content.searchIndex,
            uuid=instance_uuid,
            vmSearch=True,
            instanceUuid=True)
        if vm_refs:
            return vm_refs[0]

    def get_vm_moref(self, instance_uuid):
        """Get reference to the VM.
        """
        vm_ref = self.get_vm_moref_obj(instance_uuid)
        if vm_ref:
            return vm_ref.value

    def get_vm_spec(self, vm_moref):
        vm_spec = self._session.invoke_api(vim_util,
                                           'get_object_properties',
                                           self._session.vim,
                                           vm_moref, ['network'])[0]
        return vm_spec

    def _build_vm_spec_attach(self, neutron_port_id, port_mac,
                              nsx_net_id, device_type):
        # Code inspired by nova: _create_vif_spec
        client_factory = self._session.vim.client.factory
        vm_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
        device_change = client_factory.create('ns0:VirtualDeviceConfigSpec')
        device_change.operation = "add"

        net_device = client_factory.create('ns0:' + device_type)
        net_device.key = -47
        net_device.addressType = "manual"
        # configure the neutron port id and mac
        net_device.externalId = neutron_port_id
        net_device.macAddress = port_mac
        net_device.wakeOnLanEnabled = True

        backing = client_factory.create(
            'ns0:VirtualEthernetCardOpaqueNetworkBackingInfo')
        # configure the NSX network Id
        backing.opaqueNetworkId = nsx_net_id
        backing.opaqueNetworkType = "nsx.LogicalSwitch"
        net_device.backing = backing

        connectable_spec = client_factory.create(
            'ns0:VirtualDeviceConnectInfo')
        connectable_spec.startConnected = True
        connectable_spec.allowGuestControl = True
        connectable_spec.connected = True

        net_device.connectable = connectable_spec

        device_change.device = net_device
        vm_spec.deviceChange = [device_change]

        return vm_spec

    def attach_vm_interface(self, vm_moref, neutron_port_id,
                            port_mac, nsx_net_id, device_type):
        new_spec = self._build_vm_spec_attach(
            neutron_port_id, port_mac, nsx_net_id, device_type)
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigVM_Task',
                                        vm_moref,
                                        spec=new_spec)
        try:
            self._session.wait_for_task(task)
            LOG.info(_LI("Updated VM moref %(moref)s spec - "
                         "attached an interface"),
                     {'moref': vm_moref.value})
        except Exception as e:
            LOG.error(_LE("Failed to reconfigure VM %(moref)s spec: %(e)s"),
                      {'moref': vm_moref.value, 'e': e})

    def _build_vm_spec_detach(self, device):
        """Builds the vif detach config spec."""
        # Code inspired by nova: get_network_detach_config_spec
        client_factory = self._session.vim.client.factory
        config_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
        virtual_device_config = client_factory.create(
                                'ns0:VirtualDeviceConfigSpec')
        virtual_device_config.operation = "remove"
        virtual_device_config.device = device
        config_spec.deviceChange = [virtual_device_config]
        return config_spec

    def detach_vm_interface(self, vm_moref, device):
        new_spec = self._build_vm_spec_detach(device)
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigVM_Task',
                                        vm_moref,
                                        spec=new_spec)
        try:
            self._session.wait_for_task(task)
            LOG.info(_LI("Updated VM %(moref)s spec - detached an interface"),
                     {'moref': vm_moref.value})
        except Exception as e:
            LOG.error(_LE("Failed to reconfigure vm moref %(moref)s: %(e)s"),
                      {'moref': vm_moref.value, 'e': e})

    def get_vm_interfaces_info(self, vm_moref):
        hardware_devices = self._session.invoke_api(vim_util,
                                                    "get_object_property",
                                                    self._session.vim,
                                                    vm_moref,
                                                    "config.hardware.device")
        return hardware_devices
