# Copyright 2016 VMware, Inc.
#
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

import abc

import six

from oslo_log import log as logging

from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import driver as neutron_driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron_lib.plugins import directory

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NsxIpamBase(object):
    @classmethod
    def get_core_plugin(cls):
        return directory.get_plugin()

    @property
    def _nsxlib(self):
        p = self.get_core_plugin()
        if p.is_tvd_plugin():
            # get the NSX-T sub-plugin
            p = p.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_T)
        elif p.plugin_type() != projectpluginmap.NsxPlugins.NSX_T:
            # Non NSX-T plugin
            return
        return p.nsxlib

    @property
    def _vcns(self):
        p = self.get_core_plugin()
        if p.is_tvd_plugin():
            # get the NSX-V sub-plugin
            p = p.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_V)
        elif p.plugin_type() != projectpluginmap.NsxPlugins.NSX_V:
            # Non NSX-V plugin
            return
        return p.nsx_v.vcns

    @classmethod
    def _fetch_subnet(cls, context, id):
        p = cls.get_core_plugin()
        return p._get_subnet(context, id)

    @classmethod
    def _fetch_network(cls, context, id):
        p = cls.get_core_plugin()
        return p.get_network(context, id)


class NsxSubnetRequestFactory(ipam_req.SubnetRequestFactory, NsxIpamBase):
    """Builds request using subnet info, including the network id"""

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        req = super(NsxSubnetRequestFactory, cls).get_request(
            context, subnet, subnetpool)
        # Add the network id into the request
        if 'network_id' in subnet:
            req.network_id = subnet['network_id']

        return req


class NsxAbstractIpamDriver(subnet_alloc.SubnetAllocator, NsxIpamBase):
    """Abstract IPAM Driver For NSX."""

    def __init__(self, subnetpool, context):
        super(NsxAbstractIpamDriver, self).__init__(subnetpool, context)
        # in case of unsupported networks (or pre-upgrade networks)
        # the neutron internal driver will be used
        self.default_ipam = neutron_driver.NeutronDbPool(subnetpool, context)

        # Mark which updates to the pool are supported
        # (The NSX-v  backend does not support changing the ip pool cidr
        # or gateway)
        self.support_update_gateway = False
        self.support_update_pools = False

    def _is_supported_net(self, subnet_request):
        """By default - all networks are supported"""
        return True

    def get_subnet_request_factory(self):
        # override the OOB factory to add the network ID
        return NsxSubnetRequestFactory

    @abc.abstractproperty
    def _subnet_class(self):
        """Return the class of the subnet that should be used."""
        pass

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet."""
        nsx_pool_id = nsx_db.get_nsx_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            return self.default_ipam.get_subnet(subnet_id)

        return self._subnet_class.load(subnet_id, nsx_pool_id, self._context)

    @abc.abstractmethod
    def allocate_backend_pool(self, subnet_request):
        """Create a pool on the NSX backend and return its ID"""
        pass

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided request."""
        if not self._is_supported_net(subnet_request=subnet_request):
            # fallback to the neutron internal driver implementation
            return self.default_ipam.allocate_subnet(subnet_request)

        if self._subnetpool:
            subnet = super(NsxAbstractIpamDriver, self).allocate_subnet(
                subnet_request)
            subnet_request = subnet.get_details()

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))

        # Add the pool to the NSX backend
        nsx_pool_id = self.allocate_backend_pool(subnet_request)

        # Add the pool to the DB
        nsx_db.add_nsx_ipam_subnet_pool(self._context.session,
                                        subnet_request.subnet_id,
                                        nsx_pool_id)
        # return the subnet object
        return self._subnet_class.load(subnet_request.subnet_id, nsx_pool_id,
                                       self._context,
                                       tenant_id=subnet_request.tenant_id)

    @abc.abstractmethod
    def update_backend_pool(self, nsx_pool_id, subnet_request):
        pass

    def _raise_update_not_supported(self):
        msg = _('Changing the subnet range or gateway is not supported')
        raise ipam_exc.IpamValueInvalid(message=msg)

    def update_subnet(self, subnet_request):
        """Update subnet info in the IPAM driver.

        Do the update only if the specific change is supported by the backend
        """
        nsx_pool_id = nsx_db.get_nsx_ipam_pool_for_subnet(
            self._context.session, subnet_request.subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            return self.default_ipam.update_subnet(
                subnet_request)

        # get the current pool data
        curr_subnet = self._subnet_class.load(
            subnet_request.subnet_id, nsx_pool_id,
            self._context, tenant_id=subnet_request.tenant_id).get_details()

        # check if the gateway changed
        gateway_changed = False
        if (str(subnet_request.gateway_ip) != str(curr_subnet.gateway_ip)):
            if not self.support_update_gateway:
                self._raise_update_not_supported()
            gateway_changed = True

        # check that the prefix / cidr / pools changed
        pools_changed = False
        if subnet_request.prefixlen != curr_subnet.prefixlen:
            if not self.support_update_pools:
                self._raise_update_not_supported()
            pools_changed = True

        if subnet_request.subnet_cidr[0] != curr_subnet.subnet_cidr[0]:
            if not self.support_update_pools:
                self._raise_update_not_supported()
            pools_changed = True

        if (len(subnet_request.allocation_pools) !=
            len(curr_subnet.allocation_pools)):
            if not self.support_update_pools:
                self._raise_update_not_supported()
            pools_changed = True

        if (len(subnet_request.allocation_pools) !=
            len(curr_subnet.allocation_pools)):
            if not self.support_update_pools:
                self._raise_update_not_supported()
            pools_changed = True
        else:
            for pool_ind in range(len(subnet_request.allocation_pools)):
                pool_req = subnet_request.allocation_pools[pool_ind]
                curr_pool = curr_subnet.allocation_pools[pool_ind]
                if (pool_req.first != curr_pool.first or
                    pool_req.last != curr_pool.last):
                    if not self.support_update_pools:
                        self._raise_update_not_supported()
                    pools_changed = True

        # update the relevant attributes at the backend pool
        if gateway_changed or pools_changed:
            self.update_backend_pool(nsx_pool_id, subnet_request)

    @abc.abstractmethod
    def delete_backend_pool(self, nsx_pool_id):
        pass

    def remove_subnet(self, subnet_id):
        """Delete an IPAM subnet pool from backend & DB."""
        nsx_pool_id = nsx_db.get_nsx_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            self.default_ipam.remove_subnet(subnet_id)
            return

        # Delete from backend
        self.delete_backend_pool(nsx_pool_id)

        # delete pool from DB
        nsx_db.del_nsx_ipam_subnet_pool(self._context.session,
                                        subnet_id, nsx_pool_id)


class NsxIpamSubnetManager(object):

    def __init__(self, neutron_subnet_id):
        self._neutron_subnet_id = neutron_subnet_id

    @property
    def neutron_id(self):
        return self._neutron_subnet_id


class NsxAbstractIpamSubnet(ipam_base.Subnet, NsxIpamBase):
    """Manage IP addresses for the NSX IPAM driver."""

    def __init__(self, subnet_id, nsx_pool_id, ctx, tenant_id):
        self._subnet_id = subnet_id
        self._nsx_pool_id = nsx_pool_id
        self._context = ctx
        self._tenant_id = tenant_id
        #TODO(asarfaty): this subnet_manager is currently required by the
        #pluggable-ipam-driver
        self.subnet_manager = NsxIpamSubnetManager(self._subnet_id)

    @classmethod
    def load(cls, neutron_subnet_id, nsx_pool_id, ctx, tenant_id=None):
        """Load an IPAM subnet object given its neutron ID."""
        return cls(neutron_subnet_id, nsx_pool_id, ctx, tenant_id)

    def allocate(self, address_request):
        """Allocate an IP from the pool"""
        return self.backend_allocate(address_request)

    @abc.abstractmethod
    def backend_allocate(self, address_request):
        pass

    def deallocate(self, address):
        """Return an IP to the pool"""
        self.backend_deallocate(address)

    @abc.abstractmethod
    def backend_deallocate(self, address):
        pass

    def update_allocation_pools(self, pools, cidr):
        # Not supported
        pass
