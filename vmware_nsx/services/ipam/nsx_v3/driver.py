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

from oslo_log import log as logging

from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req

from vmware_nsx._i18n import _
from vmware_nsx.services.ipam.common import driver as common
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as error

LOG = logging.getLogger(__name__)


class Nsxv3IpamDriver(common.NsxAbstractIpamDriver):
    """IPAM Driver For NSX-V3 networks."""

    def __init__(self, subnetpool, context):
        super(Nsxv3IpamDriver, self).__init__(subnetpool, context)
        self.nsxlib_ipam = self._nsxlib.ip_pool

        # Mark which updates to the pool are supported
        self.support_update_gateway = True
        self.support_update_pools = True

    @property
    def _subnet_class(self):
        return Nsxv3IpamSubnet

    def _get_cidr_from_request(self, subnet_request):
        return "%s/%s" % (subnet_request.subnet_cidr[0],
                          subnet_request.prefixlen)

    def _get_ranges_from_request(self, subnet_request):
        if subnet_request.allocation_pools:
            ranges = [
                {'start': str(pool[0]), 'end': str(pool[-1])}
                for pool in subnet_request.allocation_pools]
        else:
            ranges = []
        return ranges

    def _is_supported_net(self, subnet_request):
        """This driver doesn't support multicast cidrs"""
        if not hasattr(subnet_request, "subnet_cidr"):
            return True
        net = netaddr.IPNetwork(subnet_request.subnet_cidr[0])
        return not net.is_multicast()

    def allocate_backend_pool(self, subnet_request):
        """Create a pool on the NSX backend and return its ID"""
        # name/description length on backend is long, so there is no problem
        name = 'subnet_' + subnet_request.subnet_id
        description = 'OS IP pool for subnet ' + subnet_request.subnet_id
        try:
            response = self.nsxlib_ipam.create(
                self._get_cidr_from_request(subnet_request),
                allocation_ranges=self._get_ranges_from_request(
                    subnet_request),
                display_name=name,
                description=description,
                gateway_ip=subnet_request.gateway_ip)
            nsx_pool_id = response['id']
        except Exception as e:
            #TODO(asarfaty): handle specific errors
            msg = _('Failed to create subnet IPAM: %s') % e
            raise ipam_exc.IpamValueInvalid(message=msg)
        return nsx_pool_id

    def delete_backend_pool(self, nsx_pool_id):
        # Because of the delete_subnet flow in the neutron plugin,
        # some ports still hold IPs from this pool.
        # Those ports be deleted shortly after this function.
        # We need to release those IPs before deleting the backed pool,
        # or else it will fail.
        pool_allocations = self.nsxlib_ipam.get_allocations(nsx_pool_id)
        if pool_allocations and pool_allocations.get('result_count'):
            for allocation in pool_allocations.get('results', []):
                ip_addr = allocation.get('allocation_id')
                try:
                    self.nsxlib_ipam.release(nsx_pool_id, ip_addr)
                except Exception as e:
                    LOG.warning("Failed to release ip %(ip)s from pool "
                                "%(pool)s: %(e)s",
                                {'ip': ip_addr, 'pool': nsx_pool_id, 'e': e})
        try:
            self.nsxlib_ipam.delete(nsx_pool_id)
        except Exception as e:
            LOG.error("Failed to delete IPAM from backend: %s", e)
            # Continue anyway, since this subnet was already removed

    def update_backend_pool(self, nsx_pool_id, subnet_request):
        update_args = {
            'cidr': self._get_cidr_from_request(subnet_request),
            'allocation_ranges': self._get_ranges_from_request(subnet_request),
            'gateway_ip': subnet_request.gateway_ip}
        try:
            self.nsxlib_ipam.update(
                nsx_pool_id, **update_args)
        except nsx_lib_exc.ManagerError as e:
            LOG.error("NSX IPAM failed to update pool %(id)s: "
                      " %(e)s; code %(code)s",
                      {'e': e,
                       'id': nsx_pool_id,
                       'code': e.error_code})
            if (e.error_code == error.ERR_CODE_IPAM_RANGE_MODIFY or
                e.error_code == error.ERR_CODE_IPAM_RANGE_DELETE or
                e.error_code == error.ERR_CODE_IPAM_RANGE_SHRUNK):
                # The change is not allowed: already allocated IPs out of
                # the new range
                raise ipam_exc.InvalidSubnetRequest(
                    reason=_("Already allocated IPs outside of the updated "
                             "pools"))
        except Exception as e:
            # unexpected error
            msg = _('Failed to update subnet IPAM: %s') % e
            raise ipam_exc.IpamValueInvalid(message=msg)


class Nsxv3IpamSubnet(common.NsxAbstractIpamSubnet):
    """Manage IP addresses for the NSX V3 IPAM driver."""

    def __init__(self, subnet_id, nsx_pool_id, ctx, tenant_id):
        super(Nsxv3IpamSubnet, self).__init__(
            subnet_id, nsx_pool_id, ctx, tenant_id)
        self.nsxlib_ipam = self._nsxlib.ip_pool

    def backend_allocate(self, address_request):
        try:
            # allocate a specific IP
            if isinstance(address_request, ipam_req.SpecificAddressRequest):
                # This handles both specific and automatic address requests
                ip_address = str(address_request.address)
                # If this is the subnet gateway IP - no need to allocate it
                subnet = self.get_details()
                if str(subnet.gateway_ip) == ip_address:
                    LOG.info("Skip allocation of gateway-ip for pool %s",
                             self._nsx_pool_id)
                    return ip_address
            else:
                # Allocate any free IP
                ip_address = None
            response = self.nsxlib_ipam.allocate(self._nsx_pool_id,
                                                 ip_addr=ip_address)
            ip_address = response['allocation_id']
        except nsx_lib_exc.ManagerError as e:
            LOG.error("NSX IPAM failed to allocate ip %(ip)s of subnet "
                      "%(id)s: %(e)s; code %(code)s",
                      {'e': e,
                       'ip': ip_address,
                       'id': self._subnet_id,
                       'code': e.error_code})
            if e.error_code == error.ERR_CODE_IPAM_POOL_EXHAUSTED:
                # No more IP addresses available on the pool
                raise ipam_exc.IpAddressGenerationFailure(
                    subnet_id=self._subnet_id)
            if e.error_code == error.ERR_CODE_IPAM_SPECIFIC_IP:
                # The NSX backend  does not support allocation of specific IPs
                # prior to version 2.0.
                msg = (_("NSX-V3 IPAM driver does not support allocation of a "
                         "specific ip %s for port") % ip_address)
                raise NotImplementedError(msg)
            if e.error_code == error.ERR_CODE_IPAM_IP_ALLOCATED:
                # This IP is already in use
                raise ipam_exc.IpAddressAlreadyAllocated(
                    ip=ip_address, subnet_id=self._subnet_id)
            if e.error_code == error.ERR_CODE_OBJECT_NOT_FOUND:
                msg = (_("NSX-V3 IPAM failed to allocate: pool %s was not "
                         "found") % self._nsx_pool_id)
                raise ipam_exc.IpamValueInvalid(message=msg)
            else:
                # another backend error
                raise ipam_exc.IPAllocationFailed()
        except Exception as e:
            LOG.error("NSX IPAM failed to allocate ip %(ip)s of subnet "
                      "%(id)s: %(e)s",
                      {'e': e,
                       'ip': ip_address,
                       'id': self._subnet_id})
            # handle unexpected failures
            raise ipam_exc.IPAllocationFailed()
        return ip_address

    def backend_deallocate(self, ip_address):
        # If this is the subnet gateway IP - no need to allocate it
        subnet = self.get_details()
        if str(subnet.gateway_ip) == ip_address:
            LOG.info("Skip deallocation of gateway-ip for pool %s",
                     self._nsx_pool_id)
            return
        try:
            self.nsxlib_ipam.release(self._nsx_pool_id, ip_address)
        except nsx_lib_exc.ManagerError as e:
            # fail silently
            LOG.error("NSX IPAM failed to free ip %(ip)s of subnet "
                      "%(id)s: %(e)s; code %(code)s",
                      {'e': e,
                       'ip': ip_address,
                       'id': self._subnet_id,
                       'code': e.error_code})

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        # get the pool from the backend
        try:
            pool_details = self.nsxlib_ipam.get(self._nsx_pool_id)
        except Exception as e:
            msg = _('Failed to get details for nsx pool: %(id)s: '
                    '%(e)s') % {'id': self._nsx_pool_id, 'e': e}
            raise ipam_exc.IpamValueInvalid(message=msg)

        first_range = pool_details.get('subnets', [None])[0]
        if not first_range:
            msg = _('Failed to get details for nsx pool: %(id)s') % {
                'id': self._nsx_pool_id}
            raise ipam_exc.IpamValueInvalid(message=msg)

        cidr = first_range.get('cidr')
        gateway_ip = first_range.get('gateway_ip')
        pools = []
        for subnet in pool_details.get('subnets', []):
            for ip_range in subnet.get('allocation_ranges', []):
                pools.append(netaddr.IPRange(ip_range.get('start'),
                                             ip_range.get('end')))
        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self._subnet_id,
            cidr, gateway_ip=gateway_ip, allocation_pools=pools)
