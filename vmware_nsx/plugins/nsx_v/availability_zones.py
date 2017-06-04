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

from vmware_nsx._i18n import _
from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc

DEFAULT_NAME = common_az.DEFAULT_NAME


class NsxVAvailabilityZone(common_az.ConfiguredAvailabilityZone):

    def init_from_config_line(self, config_line):
        values = config_line.split(':')
        if len(values) < 4 or len(values) > 5:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="availability_zones",
                opt_value=config_line,
                reason=_("Expected 4 or 5 values per zone"))

        self.resource_pool = values[1]
        self.datastore_id = values[2]

        # validate the edge_ha
        if values[3].lower() == "true":
            self.edge_ha = True
        elif values[3].lower() == "false":
            self.edge_ha = False
        else:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="availability_zones",
                opt_value=config_line,
                reason=_("Expected the 4th value to be true/false"))

        # HA datastore id is relevant only with edge_ha
        if not self.edge_ha and len(values) == 5:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="availability_zones",
                opt_value=config_line,
                reason=_("Expected HA datastore ID only when edge_ha is "
                         "enabled"))

        self.ha_datastore_id = values[4] if len(values) == 5 else None

        # Some parameters are not supported in this format.
        # using the global ones instead.
        self.ha_placement_random = cfg.CONF.nsxv.ha_placement_random
        self.datacenter_moid = cfg.CONF.nsxv.datacenter_moid
        self.backup_edge_pool = cfg.CONF.nsxv.backup_edge_pool
        self.external_network = cfg.CONF.nsxv.external_network
        self.vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id
        self.dvs_id = cfg.CONF.nsxv.dvs_id
        self.edge_host_groups = cfg.CONF.nsxv.edge_host_groups
        self.exclusive_dhcp_edge = cfg.CONF.nsxv.exclusive_dhcp_edge

        # No support for metadata per az
        self.az_metadata_support = False
        self.mgt_net_moid = None
        self.mgt_net_proxy_ips = []
        self.mgt_net_proxy_netmask = None
        self.mgt_net_default_gateway = None

    def init_from_config_section(self, az_name):
        az_info = config.get_nsxv_az_opts(az_name)
        self.resource_pool = az_info.get('resource_pool_id')
        if not self.resource_pool:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="resource_pool_id",
                opt_value='None',
                reason=(_("resource_pool_id for availability zone %s "
                          "must be defined") % az_name))
        self.datastore_id = az_info.get('datastore_id')
        if not self.datastore_id:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="datastore_id",
                opt_value='None',
                reason=(_("datastore_id for availability zone %s "
                          "must be defined") % az_name))
        self.edge_ha = az_info.get('edge_ha', False)
        # The HA datastore can be empty
        self.ha_datastore_id = (az_info.get('ha_datastore_id')
                                if self.edge_ha else None)

        if self.ha_datastore_id and not self.edge_ha:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="ha_datastore_id",
                opt_value=self.ha_datastore_id,
                reason=_("Expected HA datastore ID only when edge_ha is "
                         "enabled for availability zone %s") % az_name)

        # The optional parameters will get the global values if not
        # defined for this AZ
        self.ha_placement_random = az_info.get('ha_placement_random')
        if self.ha_placement_random is None:
            self.ha_placement_random = (
                cfg.CONF.nsxv.ha_placement_random)

        self.datacenter_moid = az_info.get('datacenter_moid')
        if not self.datacenter_moid:
            self.datacenter_moid = cfg.CONF.nsxv.datacenter_moid

        self.backup_edge_pool = az_info.get('backup_edge_pool', [])
        if not self.backup_edge_pool:
            self.backup_edge_pool = cfg.CONF.nsxv.backup_edge_pool

        self.external_network = az_info.get('external_network')
        if not self.external_network:
            self.external_network = cfg.CONF.nsxv.external_network

        self.vdn_scope_id = az_info.get('vdn_scope_id')
        if not self.vdn_scope_id:
            self.vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id

        self.dvs_id = az_info.get('dvs_id')
        if not self.dvs_id:
            self.dvs_id = cfg.CONF.nsxv.dvs_id

        self.edge_host_groups = az_info.get('edge_host_groups', [])
        if not self.edge_host_groups:
            self.edge_host_groups = cfg.CONF.nsxv.edge_host_groups

        self.exclusive_dhcp_edge = az_info.get('exclusive_dhcp_edge', False)

        # Support for metadata per az only if configured, and different
        # from the global one
        self.mgt_net_proxy_ips = az_info.get('mgt_net_proxy_ips')
        if self.mgt_net_proxy_ips:
            # make sure there are no over lapping ips with the
            # global configuration
            if (set(self.mgt_net_proxy_ips) &
                set(cfg.CONF.nsxv.mgt_net_proxy_ips)):
                raise nsx_exc.NsxInvalidConfiguration(
                    opt_name="mgt_net_proxy_ips",
                    opt_value='None',
                    reason=(_("mgt_net_proxy_ips for availability zone "
                              "%s must be different from global one") %
                            az_name))

            self.az_metadata_support = True
            self.mgt_net_moid = az_info.get('mgt_net_moid')
            if not self.mgt_net_moid:
                self.mgt_net_moid = cfg.CONF.nsxv.mgt_net_moid

            self.mgt_net_proxy_netmask = az_info.get(
                'mgt_net_proxy_netmask')
            if not self.mgt_net_proxy_netmask:
                self.mgt_net_proxy_netmask = (
                    cfg.CONF.nsxv.mgt_net_proxy_netmask)

            self.mgt_net_default_gateway = az_info.get(
                'mgt_net_default_gateway')
            if not self.mgt_net_default_gateway:
                self.mgt_net_default_gateway = (
                    cfg.CONF.nsxv.mgt_net_default_gateway)

        else:
            self.az_metadata_support = False
            self.mgt_net_moid = None
            self.mgt_net_proxy_ips = []
            self.mgt_net_proxy_netmask = None
            self.mgt_net_default_gateway = None

    def init_default_az(self):
        # use the default configuration
        self.resource_pool = cfg.CONF.nsxv.resource_pool_id
        self.datastore_id = cfg.CONF.nsxv.datastore_id
        self.edge_ha = cfg.CONF.nsxv.edge_ha
        self.ha_datastore_id = cfg.CONF.nsxv.ha_datastore_id
        self.ha_placement_random = cfg.CONF.nsxv.ha_placement_random
        self.datacenter_moid = cfg.CONF.nsxv.datacenter_moid
        self.backup_edge_pool = cfg.CONF.nsxv.backup_edge_pool
        self.az_metadata_support = True
        self.mgt_net_moid = cfg.CONF.nsxv.mgt_net_moid
        self.mgt_net_proxy_ips = cfg.CONF.nsxv.mgt_net_proxy_ips
        self.mgt_net_proxy_netmask = cfg.CONF.nsxv.mgt_net_proxy_netmask
        self.mgt_net_default_gateway = (
            cfg.CONF.nsxv.mgt_net_default_gateway)
        self.external_network = cfg.CONF.nsxv.external_network
        self.vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id
        self.dvs_id = cfg.CONF.nsxv.dvs_id
        self.edge_host_groups = cfg.CONF.nsxv.edge_host_groups
        self.exclusive_dhcp_edge = cfg.CONF.nsxv.exclusive_dhcp_edge

    def supports_metadata(self):
        # Return True if this az has it's own metadata configuration
        # If False - it uses the global metadata (if defined)
        return self.az_metadata_support


class NsxVAvailabilityZones(common_az.ConfiguredAvailabilityZones):

    def __init__(self):
        super(NsxVAvailabilityZones, self).__init__(
            cfg.CONF.nsxv.availability_zones,
            NsxVAvailabilityZone)

    def get_inventory(self):
        """Return a set of relevant resources in all the availability zones
        """
        resources = set()
        for az in self.list_availability_zones_objects():
            if az.resource_pool:
                resources.add(az.resource_pool)
            if az.datastore_id:
                resources.add(az.datastore_id)
            if az.ha_datastore_id:
                resources.add(az.ha_datastore_id)

        return resources

    def get_unique_non_default_param(self, param_name):
        """Return a set of all configured values of one of az params

        Ignore the value of the default AZ
        """
        resources = set()
        default_val = None
        for az in self.list_availability_zones_objects():
            az_val = getattr(az, param_name)
            if az.is_default():
                default_val = az_val
            elif az_val:
                resources.add(az_val)
        # remove the default value
        if default_val:
            resources.discard(default_val)
        return resources

    def get_additional_vdn_scope(self):
        return self.get_unique_non_default_param("vdn_scope_id")

    def get_additional_mgt_net(self):
        return self.get_unique_non_default_param("mgt_net_moid")

    def get_additional_ext_net(self):
        return self.get_unique_non_default_param("external_network")

    def get_additional_datacenter(self):
        return self.get_unique_non_default_param("datacenter_moid")

    def get_additional_dvs_ids(self):
        return self.get_unique_non_default_param("dvs_id")
