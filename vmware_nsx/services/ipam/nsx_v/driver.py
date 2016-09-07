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

import netaddr
import xml.etree.ElementTree as et

from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as pnet
from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import driver as neutron_driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron import manager
from neutron_lib.api import validators
from oslo_log import log as logging

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import constants
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vc_exc

LOG = logging.getLogger(__name__)


class NsxvIpamBase(object):
    @classmethod
    def get_core_plugin(cls):
        return manager.NeutronManager.get_plugin()

    @classmethod
    def _fetch_subnet(cls, context, id):
        p = cls.get_core_plugin()
        return p._get_subnet(context, id)

    @classmethod
    def _fetch_network(cls, context, id):
        p = cls.get_core_plugin()
        return p.get_network(context, id)

    @property
    def _vcns(self):
        p = self.get_core_plugin()
        return p.nsx_v.vcns

    def _get_vcns_error_code(self, e):
        """Get the error code out of VcnsApiException"""
        try:
            desc = et.fromstring(e.response)
            return int(desc.find('errorCode').text)
        except Exception:
            LOG.error(_LE('IPAM pool: Error code not present. %s'),
                e.response)


class NsxvIpamDriver(subnet_alloc.SubnetAllocator, NsxvIpamBase):
    """IPAM Driver For NSX-V external & provider networks."""

    def __init__(self, subnetpool, context):
        super(NsxvIpamDriver, self).__init__(subnetpool, context)
        # in case of regular networks (not external, not provider net)
        # or ipv6 networks, the neutron internal driver will be used
        self.default_ipam = neutron_driver.NeutronDbPool(subnetpool, context)

    def _is_ext_or_provider_net(self, subnet_request):
        """Return True if the network of the request is external or
        provider network
        """
        network_id = subnet_request.network_id
        if network_id:
            network = self._fetch_network(self._context, network_id)
            if network.get(ext_net_extn.EXTERNAL):
                # external network
                return True
            if (validators.is_attr_set(network.get(mpnet.SEGMENTS)) or
                validators.is_attr_set(network.get(pnet.NETWORK_TYPE))):
                # provider network
                return True

        return False

    def _is_ipv6_subnet(self, subnet_request):
        """Return True if the network of the request is an ipv6 network"""
        if isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            return subnet_request.subnet_cidr.version == 6
        else:
            if subnet_request.allocation_pools:
                for pool in subnet_request.allocation_pools:
                    if pool.version == 6:
                        return True
            return False

    def _is_supported_net(self, subnet_request):
        """This driver supports only ipv4 external/provider networks"""
        return (self._is_ext_or_provider_net(subnet_request) and
                not self._is_ipv6_subnet(subnet_request))

    def get_subnet_request_factory(self):
        # override the OOB factory to add the network ID
        return NsxvSubnetRequestFactory

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet."""
        nsx_pool_id = nsxv_db.get_nsxv_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            return self.default_ipam.get_subnet(subnet_id)

        return NsxvIpamSubnet.load(subnet_id, nsx_pool_id, self._context)

    def allocate_backend_pool(self, subnet_request):
        """Create a pool on the NSX backend and return its ID"""
        if subnet_request.allocation_pools:
            ranges = [
                {'ipRangeDto':
                    {'startAddress': netaddr.IPAddress(pool.first),
                     'endAddress': netaddr.IPAddress(pool.last)}}
                for pool in subnet_request.allocation_pools]
        else:
            ranges = []

        request = {'ipamAddressPool':
            # max name length on backend is 255, so there is no problem here
            {'name': 'subnet_' + subnet_request.subnet_id,
             'prefixLength': subnet_request.prefixlen,
             'gateway': subnet_request.gateway_ip,
             'ipRanges': ranges}}

        try:
            response = self._vcns.create_ipam_ip_pool(request)
            nsx_pool_id = response[1]
        except vc_exc.VcnsApiException as e:
            msg = _('Failed to create subnet IPAM: %s') % e
            raise ipam_exc.IpamValueInvalid(message=msg)

        return nsx_pool_id

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided request."""
        if not self._is_supported_net(subnet_request=subnet_request):
            # fallback to the neutron internal driver implementation
            return self.default_ipam.allocate_subnet(subnet_request)

        if self._subnetpool:
            subnet = super(NsxvIpamDriver, self).allocate_subnet(
                subnet_request)
            subnet_request = subnet.get_details()

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))

        # Add the pool to the NSX backend
        nsx_pool_id = self.allocate_backend_pool(subnet_request)

        # Add the pool to the DB
        nsxv_db.add_nsxv_ipam_subnet_pool(self._context.session,
                                          subnet_request.subnet_id,
                                          nsx_pool_id)
        # return the subnet object
        return NsxvIpamSubnet(subnet_request.subnet_id, nsx_pool_id,
                              self._context, subnet_request.tenant_id)

    def _raise_update_not_supported(self):
        msg = _('Changing the subnet range or gateway is not supported')
        raise ipam_exc.IpamValueInvalid(message=msg)

    def update_subnet(self, subnet_request):
        """Update subnet info in the IPAM driver.

        The NSX backend does not support changing the ip pool cidr or gateway
        """
        nsx_pool_id = nsxv_db.get_nsxv_ipam_pool_for_subnet(
            self._context.session, subnet_request.subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            return self.default_ipam.update_subnet(
                subnet_request)

        # get the current pool data
        curr_subnet = NsxvIpamSubnet(
            subnet_request.subnet_id, nsx_pool_id,
            self._context, subnet_request.tenant_id).get_details()

        # check that the gateway / cidr / pools did not change
        if str(subnet_request.gateway_ip) != str(curr_subnet.gateway_ip):
            self._raise_update_not_supported()

        if subnet_request.prefixlen != curr_subnet.prefixlen:
            self._raise_update_not_supported()

        if (len(subnet_request.allocation_pools) !=
            len(curr_subnet.allocation_pools)):
            self._raise_update_not_supported()

        for pool_ind in range(len(subnet_request.allocation_pools)):
            pool_req = subnet_request.allocation_pools[pool_ind]
            curr_pool = curr_subnet.allocation_pools[pool_ind]
            if (pool_req.first != curr_pool.first or
                pool_req.last != curr_pool.last):
                self._raise_update_not_supported()

    def remove_subnet(self, subnet_id):
        """Delete an IPAM subnet pool from backend & DB."""
        nsx_pool_id = nsxv_db.get_nsxv_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # Unsupported (or pre-upgrade) network
            self.default_ipam.remove_subnet(subnet_id)
            return

        with locking.LockManager.get_lock('nsx-ipam-' + nsx_pool_id):
            # Delete from backend
            try:
                self._vcns.delete_ipam_ip_pool(nsx_pool_id)
            except vc_exc.VcnsApiException as e:
                LOG.error(_LE("Failed to delete IPAM from backend: %s"), e)
                # Continue anyway, since this subnet was already removed

            # delete pool from DB
            nsxv_db.del_nsxv_ipam_subnet_pool(self._context.session,
                                              subnet_id, nsx_pool_id)


class NsxvIpamSubnet(ipam_base.Subnet, NsxvIpamBase):
    """Manage IP addresses for the NSX IPAM driver."""

    def __init__(self, subnet_id, nsx_pool_id, ctx, tenant_id):
        self._subnet_id = subnet_id
        self._nsx_pool_id = nsx_pool_id
        self._context = ctx
        self._tenant_id = tenant_id

    @classmethod
    def load(cls, neutron_subnet_id, nsx_pool_id, ctx, tenant_id=None):
        """Load an IPAM subnet object given its neutron ID."""
        return cls(neutron_subnet_id, nsx_pool_id, ctx, tenant_id)

    def allocate(self, address_request):
        """Allocate an IP from the pool"""
        with locking.LockManager.get_lock('nsx-ipam-' + self._nsx_pool_id):
            return self._allocate(address_request)

    def _allocate(self, address_request):
        try:
            # allocate a specific IP
            if isinstance(address_request, ipam_req.SpecificAddressRequest):
                # This handles both specific and automatic address requests
                ip_address = str(address_request.address)
                self._vcns.allocate_ipam_ip_from_pool(self._nsx_pool_id,
                                                      ip_addr=ip_address)
            else:
                # Allocate any free IP
                response = self._vcns.allocate_ipam_ip_from_pool(
                    self._nsx_pool_id)[1]
                # get the ip from the response
                root = et.fromstring(response)
                ip_address = root.find('ipAddress').text
        except vc_exc.VcnsApiException as e:
            # handle backend failures
            error_code = self._get_vcns_error_code(e)
            if error_code == constants.NSX_ERROR_IPAM_ALLOCATE_IP_USED:
                # This IP is already in use
                raise ipam_exc.IpAddressAlreadyAllocated(
                    ip=ip_address, subnet_id=self._subnet_id)
            if error_code == constants.NSX_ERROR_IPAM_ALLOCATE_ALL_USED:
                # No more IP addresses available on the pool
                raise ipam_exc.IpAddressGenerationFailure(
                    subnet_id=self._subnet_id)
            else:
                raise ipam_exc.IPAllocationFailed()
        return ip_address

    def deallocate(self, address):
        """Return an IP to the pool"""
        with locking.LockManager.get_lock('nsx-ipam-' + self._nsx_pool_id):
            self._deallocate(address)

    def _deallocate(self, address):
        try:
            self._vcns.release_ipam_ip_to_pool(self._nsx_pool_id, address)
        except vc_exc.VcnsApiException as e:
            LOG.error(_LE("NSX IPAM failed to free ip %(ip)s of subnet %(id)s:"
                          " %(e)s"),
                      {'e': e.response,
                       'ip': address,
                       'id': self._subnet_id})
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self._subnet_id,
                ip_address=address)

    def update_allocation_pools(self, pools, cidr):
        # Not supported
        pass

    def _get_pool_cidr(self, pool):
        # rebuild the cidr from the pool range & prefix using the first
        # range in the pool, because they all should belong to the same cidr
        cidr = '%s/%s' % (pool['ipRanges'][0]['startAddress'],
                          pool['prefixLength'])
        # convert to a proper  cidr
        cidr = netaddr.IPNetwork(cidr).cidr
        return str(cidr)

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        # get the pool from the backend
        pool_details = self._vcns.get_ipam_ip_pool(self._nsx_pool_id)[1]
        gateway_ip = pool_details['gateway']
        # rebuild the cidr from the range & prefix
        cidr = self._get_pool_cidr(pool_details)
        pools = []
        for ip_range in pool_details['ipRanges']:
            pools.append(netaddr.IPRange(ip_range['startAddress'],
                                         ip_range['endAddress']))

        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self._subnet_id,
            cidr, gateway_ip=gateway_ip, allocation_pools=pools)


class NsxvSubnetRequestFactory(ipam_req.SubnetRequestFactory, NsxvIpamBase):
    """Builds request using subnet info, including the network id"""

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        req = super(NsxvSubnetRequestFactory, cls).get_request(
            context, subnet, subnetpool)
        # Add the network id into the request
        if 'network_id' in subnet:
            req.network_id = subnet['network_id']

        return req
