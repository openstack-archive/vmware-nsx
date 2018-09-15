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

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.dvs import dvs_utils

LOG = logging.getLogger(__name__)
PORTGROUP_PREFIX = 'dvportgroup'
API_FIND_ALL_BY_UUID = 'FindAllByUuid'

# QoS related constants
QOS_IN_DIRECTION = 'incomingPackets'
QOS_AGENT_NAME = 'dvfilter-generic-vmware'
DSCP_RULE_DESCRIPTION = 'Openstack Dscp Marking RUle'


class SingleDvsManager(object):
    """Management class for dvs related tasks for the dvs plugin

    For the globally configured dvs.
    the moref of the configured DVS will be learnt. This will be used in
    the operations supported by the manager.
    """
    def __init__(self):
        self.dvs = DvsManager()
        self._dvs_moref = self._get_dvs_moref_by_name(
            self.dvs.get_vc_session(),
            dvs_utils.dvs_name_get())

    def _get_dvs_moref_by_name(self, session, dvs_name):
        """Get the moref of the configured DVS."""
        return self.dvs.get_dvs_moref_by_name(dvs_name, session)

    def add_port_group(self, net_id, vlan_tag=None, trunk_mode=False):
        return self.dvs.add_port_group(self._dvs_moref, net_id,
                                       vlan_tag=vlan_tag,
                                       trunk_mode=trunk_mode)

    def delete_port_group(self, net_id):
        return self.dvs.delete_port_group(self._dvs_moref, net_id)

    def get_port_group_info(self, net_id):
        return self.dvs.get_port_group_info(self._dvs_moref, net_id)

    def net_id_to_moref(self, net_id):
        return self.dvs._net_id_to_moref(self._dvs_moref, net_id)


class VCManagerBase(object):
    """Base class for all VC related classes, to initialize the session"""
    def __init__(self):
        """Initializer.

        A global session with the VC will be established.

        NOTE: the DVS port group name will be the Neutron network UUID.
        """
        self._session = dvs_utils.dvs_create_session()

    def get_vc_session(self):
        return self._session


class DvsManager(VCManagerBase):
    """Management class for dvs related tasks

    The dvs-id is not a class member, since multiple dvs-es can be supported.
    """

    def get_dvs_moref_by_name(self, dvs_name, session=None):
        """Get the moref of DVS."""
        if not session:
            session = self.get_vc_session()
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

    def _get_dvs_moref_by_id(self, dvs_id):
        return vim_util.get_moref(dvs_id, 'VmwareDistributedVirtualSwitch')

    def _get_vlan_spec(self, vlan_tag):
        """Gets portgroup vlan spec."""
        # Create the spec for the vlan tag
        client_factory = self._session.vim.client.factory
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
        vl_spec = client_factory.create(spec_ns)
        vl_spec.vlanId = vlan_tag
        vl_spec.inherited = '0'
        return vl_spec

    def _get_trunk_vlan_spec(self, start=0, end=4094):
        """Gets portgroup trunk vlan spec."""
        client_factory = self._session.vim.client.factory
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchTrunkVlanSpec'
        range = client_factory.create('ns0:NumericRange')
        range.start = start
        range.end = end
        vlan_tag = range
        vl_spec = client_factory.create(spec_ns)
        vl_spec.vlanId = vlan_tag
        vl_spec.inherited = '0'
        return vl_spec

    def _get_port_group_spec(self, net_id, vlan_tag, trunk_mode=False,
                             pg_spec=None):
        """Gets the port groups spec for net_id and vlan_tag."""
        client_factory = self._session.vim.client.factory
        if not pg_spec:
            pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.name = net_id
        pg_spec.type = 'ephemeral'
        config = client_factory.create('ns0:VMwareDVSPortSetting')
        if trunk_mode:
            config.vlan = self._get_trunk_vlan_spec()
        elif vlan_tag:
            config.vlan = self._get_vlan_spec(vlan_tag)

        pg_spec.defaultPortConfig = config
        return pg_spec

    def add_port_group(self, dvs_moref, net_id, vlan_tag=None,
                       trunk_mode=False):
        """Add a new port group to the configured DVS."""
        pg_spec = self._get_port_group_spec(net_id, vlan_tag,
                                            trunk_mode=trunk_mode)
        task = self._session.invoke_api(self._session.vim,
                                        'CreateDVPortgroup_Task',
                                        dvs_moref,
                                        spec=pg_spec)
        try:
            # NOTE(garyk): cache the returned moref
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception('Failed to create port group for '
                              '%(net_id)s with tag %(tag)s.',
                              {'net_id': net_id, 'tag': vlan_tag})
        LOG.info("%(net_id)s with tag %(vlan_tag)s created on %(dvs)s.",
                 {'net_id': net_id,
                  'vlan_tag': vlan_tag,
                  'dvs': dvs_moref.value})

    def _get_portgroup(self, net_id):
        """Get the port group moref of the net_id."""
        results = self._session.invoke_api(vim_util,
                                           'get_objects',
                                           self._session.vim,
                                           'DistributedVirtualPortgroup',
                                           100)
        while results:
            for pg in results.objects:
                for prop in pg.propSet:
                    if net_id == prop.val:
                        vim_util.cancel_retrieval(self._session.vim, results)
                        return pg.obj
            results = vim_util.continue_retrieval(self._session.vim, results)
        raise exceptions.NetworkNotFound(net_id=net_id)

    def _net_id_to_moref(self, dvs_moref, net_id):
        """Gets the moref for the specific neutron network."""
        # NOTE(garyk): return this from a cache if not found then invoke
        # code below.
        if dvs_moref:
            port_groups = self._session.invoke_api(vim_util,
                                                   'get_object_properties',
                                                   self._session.vim,
                                                   dvs_moref,
                                                   ['portgroup'])
            if len(port_groups) and hasattr(port_groups[0], 'propSet'):
                for prop in port_groups[0].propSet:
                    for val in prop.val[0]:
                        props = self._session.invoke_api(
                                vim_util,
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
        else:
            return self._get_portgroup(net_id)

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
        inPol = port_conf.inShapingPolicy
        if qos_data.egress.bandwidthEnabled:
            inPol.inherited = False
            inPol.enabled.inherited = False
            inPol.enabled.value = True
            inPol.averageBandwidth.inherited = False
            inPol.averageBandwidth.value = qos_data.egress.averageBandwidth
            inPol.peakBandwidth.inherited = False
            inPol.peakBandwidth.value = qos_data.egress.peakBandwidth
            inPol.burstSize.inherited = False
            inPol.burstSize.value = qos_data.egress.burstSize
        else:
            inPol.inherited = True

        outPol = port_conf.outShapingPolicy
        if qos_data.ingress.bandwidthEnabled:
            outPol.inherited = False
            outPol.enabled.inherited = False
            outPol.enabled.value = True
            outPol.averageBandwidth.inherited = False
            outPol.averageBandwidth.value = qos_data.ingress.averageBandwidth
            outPol.peakBandwidth.inherited = False
            outPol.peakBandwidth.value = qos_data.ingress.peakBandwidth
            outPol.burstSize.inherited = False
            outPol.burstSize.value = qos_data.ingress.burstSize
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
            LOG.error('Failed to get object properties of %s', pg_moref)
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
            LOG.error('Failed to reconfigure DVPortGroup %s', pg_moref)
            raise nsx_exc.DvsNotFound(dvs=pg_moref)

    # Update the dvs port groups config for a vxlan/vlan network
    # update the spec using a callback and user data
    def update_port_groups_config(self, dvs_id, net_id, net_moref,
                                  spec_update_calback, spec_update_data):
        is_vlan = self._is_vlan_network_by_moref(net_moref)
        if is_vlan:
            return self._update_net_port_groups_config(net_moref,
                                                       spec_update_calback,
                                                       spec_update_data)
        else:
            dvs_moref = self._get_dvs_moref_by_id(dvs_id)
            return self._update_vxlan_port_groups_config(dvs_moref,
                                                         net_id,
                                                         net_moref,
                                                         spec_update_calback,
                                                         spec_update_data)

    # Update the dvs port groups config for a vxlan network
    # Searching the port groups for a partial match to the network id & moref
    # update the spec using a callback and user data
    def _update_vxlan_port_groups_config(self,
                                         dvs_moref,
                                         net_id,
                                         net_moref,
                                         spec_update_calback,
                                         spec_update_data):
        port_groups = self._session.invoke_api(vim_util,
                                               'get_object_properties',
                                               self._session.vim,
                                               dvs_moref,
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

    def delete_port_group(self, dvs_moref, net_id):
        """Delete a specific port group."""
        moref = self._net_id_to_moref(dvs_moref, net_id)
        task = self._session.invoke_api(self._session.vim,
                                        'Destroy_Task',
                                        moref)
        try:
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception('Failed to delete port group for %s.',
                              net_id)
        LOG.info("%(net_id)s delete from %(dvs)s.",
                 {'net_id': net_id,
                  'dvs': dvs_moref.value})

    def get_port_group_info(self, dvs_moref, net_id):
        """Get portgroup information."""
        pg_moref = self._net_id_to_moref(dvs_moref, net_id)
        # Expand the properties to collect on need basis.
        properties = ['name']
        pg_info = self._session.invoke_api(vim_util,
                                           'get_object_properties_dict',
                                           self._session.vim,
                                           pg_moref, properties)
        return pg_info, pg_moref

    def _get_dvs_moref_from_teaming_data(self, teaming_data):
        """Get the moref dvs that belongs to the teaming data"""
        if 'switchObj' in teaming_data:
            if 'objectId' in teaming_data['switchObj']:
                dvs_id = teaming_data['switchObj']['objectId']
                return vim_util.get_moref(
                    dvs_id, 'VmwareDistributedVirtualSwitch')

    def update_port_group_spec_teaming(self, pg_spec, teaming_data):
        mapping = {'FAILOVER_ORDER': 'failover_explicit',
                   'ETHER_CHANNEL': 'loadbalance_ip',
                   'LACP_ACTIVE': 'loadbalance_ip',
                   'LACP_PASSIVE': 'loadbalance_ip',
                   'LACP_V2': 'loadbalance_ip',
                   'LOADBALANCE_SRCID': 'loadbalance_srcid',
                   'LOADBALANCE_SRCMAC': 'loadbalance_srcmac',
                   'LOADBALANCE_LOADBASED': 'loadbalance_loadbased'}
        dvs_moref = self._get_dvs_moref_from_teaming_data(teaming_data)
        port_conf = pg_spec.defaultPortConfig
        policy = port_conf.uplinkTeamingPolicy
        policy.inherited = False
        policy.policy.inherited = False
        policy.policy.value = mapping[teaming_data['teamingPolicy']]
        policy.uplinkPortOrder.inherited = False
        ports = teaming_data['failoverUplinkPortNames']
        policy.uplinkPortOrder.activeUplinkPort = ports
        # The standby port will be those not configure as active ones
        uplinks = self._session.invoke_api(vim_util,
                                           "get_object_property",
                                           self._session.vim,
                                           dvs_moref,
                                           "config.uplinkPortPolicy")
        # VC does not support LAG and normal uplinks. So need to check
        # if we need to configure standby links
        if set(ports) & set(uplinks.uplinkPortName):
            standby = list(set(uplinks.uplinkPortName) - set(ports))
            policy.uplinkPortOrder.standbyUplinkPort = standby

    def update_port_group_spec_name(self, pg_spec, name):
        pg_spec.name = name

    def update_port_group_spec_trunk(self, pg_spec, trunk_data):
        port_conf = pg_spec.defaultPortConfig
        port_conf.vlan = self._get_trunk_vlan_spec()

    def update_port_group_security_policy(self, pg_spec, status):
        policy = pg_spec.policy
        policy.securityPolicyOverrideAllowed = status

    def _update_port_security_policy(self, dvs_moref, port, status):
        client_factory = self._session.vim.client.factory
        ps = client_factory.create('ns0:DVPortConfigSpec')
        ps.key = port.portKey
        ps.operation = 'edit'
        policy = client_factory.create('ns0:DVSSecurityPolicy')
        bp = client_factory.create('ns0:BoolPolicy')
        bp.inherited = False
        bp.value = status
        policy.allowPromiscuous = bp
        policy.forgedTransmits = bp
        policy.inherited = False
        setting = client_factory.create('ns0:VMwareDVSPortSetting')
        setting.securityPolicy = policy
        ps.setting = setting
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigureDVPort_Task',
                                        dvs_moref,
                                        port=ps)
        try:
            self._session.wait_for_task(task)
            LOG.info("Updated port security status")
        except Exception as e:
            LOG.error("Failed to update port %s. Reason: %s",
                      port.key, e)


class VMManager(VCManagerBase):
    """Management class for VMs related VC tasks."""

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
        vm_specs = self._session.invoke_api(vim_util,
                                            'get_object_properties',
                                            self._session.vim,
                                            vm_moref, ['network'])
        if vm_specs:
            return vm_specs[0]

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
            LOG.info("Updated VM moref %(moref)s spec - "
                     "attached an interface",
                     {'moref': vm_moref.value})
        except Exception as e:
            LOG.error("Failed to reconfigure VM %(moref)s spec: %(e)s",
                      {'moref': vm_moref.value, 'e': e})

    def _build_vm_spec_update(self, devices):
        client_factory = self._session.vim.client.factory
        vm_spec = client_factory.create('ns0:VirtualMachineConfigSpec')
        vm_spec.deviceChange = [devices]
        return vm_spec

    def update_vm_interface(self, vm_moref, devices):
        update_spec = self._build_vm_spec_update(devices)
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigVM_Task',
                                        vm_moref,
                                        spec=update_spec)
        try:
            self._session.wait_for_task(task)
            LOG.info("Updated VM moref %(moref)s spec - "
                     "attached an interface",
                     {'moref': vm_moref.value})
        except Exception as e:
            LOG.error("Failed to reconfigure VM %(moref)s spec: %(e)s",
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
            LOG.info("Updated VM %(moref)s spec - detached an interface",
                     {'moref': vm_moref.value})
        except Exception as e:
            LOG.error("Failed to reconfigure vm moref %(moref)s: %(e)s",
                      {'moref': vm_moref.value, 'e': e})

    def get_vm_interfaces_info(self, vm_moref):
        hardware_devices = self._session.invoke_api(vim_util,
                                                    "get_object_property",
                                                    self._session.vim,
                                                    vm_moref,
                                                    "config.hardware.device")
        return hardware_devices

    def _get_device_port(self, device_id, mac_address):
        vm_moref = self.get_vm_moref_obj(device_id)
        hardware_devices = self.get_vm_interfaces_info(vm_moref)
        if not hardware_devices:
            return
        if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
            hardware_devices = hardware_devices.VirtualDevice
        for device in hardware_devices:
            if hasattr(device, 'macAddress'):
                if device.macAddress == mac_address:
                    return device.backing.port

    def update_port_security_policy(self, dvs_id, net_id, net_moref,
                                    device_id, mac_address, status):
        dvs_moref = self._get_dvs_moref_by_id(dvs_id)
        port = self._get_device_port(device_id, mac_address)
        if port:
            self._update_port_security_policy(dvs_moref, port, status)

    def update_vm_network(self, device, name='VM Network'):
        # In order to live migrate need a common network for interfaces
        client_factory = self._session.vim.client.factory
        network_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
        network_spec.operation = 'edit'
        backing = client_factory.create(
                  'ns0:VirtualEthernetCardNetworkBackingInfo')
        backing.deviceName = name
        device.backing = backing
        network_spec.device = device
        return network_spec

    def update_vm_opaque_spec(self, vif_info, device):
        """Updates the backing for the VIF spec."""
        client_factory = self._session.vim.client.factory
        network_spec = client_factory.create('ns0:VirtualDeviceConfigSpec')
        network_spec.operation = 'edit'
        backing = client_factory.create(
                'ns0:VirtualEthernetCardOpaqueNetworkBackingInfo')
        backing.opaqueNetworkId = vif_info['nsx_id']
        backing.opaqueNetworkType = 'nsx.LogicalSwitch'
        # Configure externalId
        device.externalId = vif_info['iface_id']
        device.backing = backing
        network_spec.device = device
        return network_spec

    def relocate_vm_spec(self, client_factory, respool_moref=None,
                         datastore_moref=None, host_moref=None,
                         disk_move_type="moveAllDiskBackingsAndAllowSharing"):
        rel_spec = client_factory.create('ns0:VirtualMachineRelocateSpec')
        if datastore_moref:
            datastore = vim_util.get_moref(datastore_moref, 'Datastore')
        else:
            datastore = None
        rel_spec.datastore = datastore
        host = vim_util.get_moref(host_moref, 'HostSystem')
        rel_spec.host = host
        res_pool = vim_util.get_moref(respool_moref, 'ResourcePool')
        rel_spec.pool = res_pool
        return rel_spec

    def relocate_vm(self, vm_ref, respool_moref=None, datastore_moref=None,
                    host_moref=None,
                    disk_move_type="moveAllDiskBackingsAndAllowSharing"):
        client_factory = self._session.vim.client.factory
        rel_spec = self.relocate_vm_spec(client_factory, respool_moref,
                                         datastore_moref, host_moref,
                                         disk_move_type)
        task = self._session.invoke_api(self._session.vim, "RelocateVM_Task",
                                        vm_ref, spec=rel_spec)
        self._session.wait_for_task(task)


class ClusterManager(VCManagerBase):
    """Management class for Cluster related VC tasks."""

    def _reconfigure_cluster(self, session, cluster, config_spec):
        """Reconfigure a cluster in vcenter"""
        try:
            reconfig_task = session.invoke_api(
                session.vim, "ReconfigureComputeResource_Task",
                cluster, spec=config_spec, modify=True)
            session.wait_for_task(reconfig_task)
        except Exception as excep:
            LOG.exception('Failed to reconfigure cluster %s', excep)

    def _create_vm_group_spec(self, client_factory, name, vm_refs,
                              group=None):
        if group is None:
            group = client_factory.create('ns0:ClusterVmGroup')
            group.name = name
            operation = 'add'
        else:
            operation = 'edit'

        # On vCenter UI, it is not possible to create VM group without
        # VMs attached to it. But, using APIs, it is possible to create
        # VM group without VMs attached. Therefore, check for existence
        # of vm attribute in the group to avoid exceptions
        if hasattr(group, 'vm'):
            group.vm += vm_refs
        else:
            group.vm = vm_refs

        group_spec = client_factory.create('ns0:ClusterGroupSpec')
        group_spec.operation = operation
        group_spec.info = group
        return [group_spec]

    def _create_cluster_rules_spec(self, client_factory, name, vm_group_name,
                                   host_group_name):
        rules_spec = client_factory.create('ns0:ClusterRuleSpec')
        rules_spec.operation = 'add'
        policy_class = 'ns0:ClusterVmHostRuleInfo'
        rules_info = client_factory.create(policy_class)
        rules_info.enabled = True
        rules_info.mandatory = False
        rules_info.name = name
        rules_info.vmGroupName = vm_group_name
        rules_info.affineHostGroupName = host_group_name
        rules_spec.info = rules_info
        return rules_spec

    def _group_name(self, index, host_group_names):
        return 'neutron-group-%s-%s' % (index, host_group_names[index - 1])

    def _rule_name(self, index, host_group_names):
        return 'neutron-rule-%s-%s' % (index, host_group_names[index - 1])

    def get_configured_vms(self, resource_id, host_group_names):
        n_host_groups = len(host_group_names)
        session = self._session
        resource = vim_util.get_moref(resource_id, 'ResourcePool')
        # TODO(garyk): cache the cluster details
        cluster = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, resource,
            "owner")
        cluster_config = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, cluster,
            "configurationEx")
        configured_vms = []
        for index in range(n_host_groups):
            vm_group = None
            entry_id = index + 1
            groups = []
            if hasattr(cluster_config, 'group'):
                groups = cluster_config.group
            for group in groups:
                if self._group_name(entry_id, host_group_names) == group.name:
                    vm_group = group
                    break
            if vm_group and hasattr(vm_group, 'vm'):
                for vm in vm_group.vm:
                    configured_vms.append(vm.value)
        return configured_vms

    def update_cluster_edge_failover(self, resource_id, vm_moids,
                                     host_group_names):
        """Updates cluster for vm placement using DRS"""
        session = self._session
        resource = vim_util.get_moref(resource_id, 'ResourcePool')
        # TODO(garyk): cache the cluster details
        cluster = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, resource,
            "owner")
        cluster_config = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, cluster,
            "configurationEx")
        vms = [vim_util.get_moref(vm_moid, 'VirtualMachine')
               if vm_moid else None
               for vm_moid in vm_moids]
        client_factory = session.vim.client.factory
        config_spec = client_factory.create('ns0:ClusterConfigSpecEx')
        num_host_groups = len(host_group_names)

        rules = []
        if hasattr(cluster_config, 'rule'):
            rules = cluster_config.rule

        for index, vm in enumerate(vms, start=1):
            if not vm:
                continue
            vmGroup = None
            groups = []
            if hasattr(cluster_config, 'group'):
                groups = cluster_config.group
            for group in groups:
                if self._group_name(index, host_group_names) == group.name:
                    vmGroup = group
                    break
            # Create/update the VM group
            groupSpec = self._create_vm_group_spec(
                            client_factory,
                            self._group_name(index, host_group_names),
                            [vm], vmGroup)
            config_spec.groupSpec.append(groupSpec)
            config_rule = None
            # Create the config rule if it does not exist
            for rule in rules:
                if self._rule_name(index, host_group_names) == rule.name:
                    config_rule = rule
                    break
            if config_rule is None and index <= num_host_groups:
                ruleSpec = self._create_cluster_rules_spec(
                    client_factory, self._rule_name(index, host_group_names),
                    self._group_name(index, host_group_names),
                    host_group_names[index - 1])
                config_spec.rulesSpec.append(ruleSpec)
        self._reconfigure_cluster(session, cluster, config_spec)

    def validate_host_groups(self, resource_id, host_group_names):
        session = self._session
        resource = vim_util.get_moref(resource_id, 'ResourcePool')
        cluster = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, resource,
            "owner")
        client_factory = session.vim.client.factory
        config_spec = client_factory.create('ns0:ClusterConfigSpecEx')
        cluster_config = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, cluster,
            "configurationEx")
        groups = []
        if hasattr(cluster_config, 'group'):
            groups = cluster_config.group
        for host_group_name in host_group_names:
            found = False
            for group in groups:
                if host_group_name == group.name:
                    found = True
                    break
            if not found:
                LOG.error("%s does not exist", host_group_name)
                raise exceptions.NotFound()

        update_cluster = False
        num_host_groups = len(host_group_names)
        rules = []
        if hasattr(cluster_config, 'rule'):
            rules = cluster_config.rule
        # Ensure that the VM groups are created
        for index in range(num_host_groups):
            entry_id = index + 1
            vmGroup = None
            for group in groups:
                if self._group_name(entry_id, host_group_names) == group.name:
                    vmGroup = group
                    break
            if vmGroup is None:
                groupSpec = self._create_vm_group_spec(
                                client_factory,
                                self._group_name(entry_id, host_group_names),
                                [], vmGroup)
                config_spec.groupSpec.append(groupSpec)
                update_cluster = True

            config_rule = None
            # Create the config rule if it does not exist
            for rule in rules:
                if self._rule_name(entry_id, host_group_names) == rule.name:
                    config_rule = rule
                    break
            if config_rule is None and index < num_host_groups:
                ruleSpec = self._create_cluster_rules_spec(
                    client_factory, self._rule_name(entry_id,
                                                    host_group_names),
                    self._group_name(entry_id, host_group_names),
                    host_group_names[index - 1])
                config_spec.rulesSpec.append(ruleSpec)
                update_cluster = True
        if update_cluster:
            try:
                self._reconfigure_cluster(session, cluster, config_spec)
            except Exception as e:
                LOG.error('Unable to update cluster for host groups %s', e)

    def _delete_vm_group_spec(self, client_factory, name):
        group_spec = client_factory.create('ns0:ClusterGroupSpec')
        group = client_factory.create('ns0:ClusterVmGroup')
        group.name = name
        group_spec.operation = 'remove'
        group_spec.removeKey = name
        group_spec.info = group
        return [group_spec]

    def _delete_cluster_rules_spec(self, client_factory, rule):
        rules_spec = client_factory.create('ns0:ClusterRuleSpec')
        rules_spec.operation = 'remove'
        rules_spec.removeKey = int(rule.key)
        policy_class = 'ns0:ClusterVmHostRuleInfo'
        rules_info = client_factory.create(policy_class)
        rules_info.name = rule.name
        rules_info.vmGroupName = rule.vmGroupName
        rules_info.affineHostGroupName = rule.affineHostGroupName
        rules_spec.info = rules_info
        return rules_spec

    def cluster_host_group_cleanup(self, resource_id, host_group_names):
        n_host_groups = len(host_group_names)
        session = self._session
        resource = vim_util.get_moref(resource_id, 'ResourcePool')
        # TODO(garyk): cache the cluster details
        cluster = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, resource,
            "owner")
        client_factory = session.vim.client.factory
        config_spec = client_factory.create('ns0:ClusterConfigSpecEx')
        cluster_config = session.invoke_api(
            vim_util, "get_object_property", self._session.vim, cluster,
            "configurationEx")
        groups = []
        if hasattr(cluster_config, 'group'):
            groups = cluster_config.group
        rules = []
        if hasattr(cluster_config, 'rule'):
            rules = cluster_config.rule

        groupSpec = []
        ruleSpec = []
        for index in range(n_host_groups):
            entry_id = index + 1
            for group in groups:
                if self._group_name(entry_id, host_group_names) == group.name:
                    groupSpec.append(self._delete_vm_group_spec(
                        client_factory, group.name))
            # Delete the config rule if it exists
            for rule in rules:
                if self._rule_name(entry_id, host_group_names) == rule.name:
                    ruleSpec.append(self._delete_cluster_rules_spec(
                        client_factory, rule))

        if groupSpec:
            config_spec.groupSpec = groupSpec
        if ruleSpec:
            config_spec.rulesSpec = ruleSpec
        if groupSpec or ruleSpec:
            self._reconfigure_cluster(session, cluster, config_spec)


class VCManager(DvsManager, VMManager, ClusterManager):
    """Management class for all vc related tasks."""
    pass
