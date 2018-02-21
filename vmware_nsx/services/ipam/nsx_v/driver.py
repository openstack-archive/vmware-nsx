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

import xml.etree.ElementTree as et

import netaddr
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import multiprovidernet as mpnet_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.plugins.nsx_v.vshield.common import constants
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vc_exc
from vmware_nsx.services.ipam.common import driver as common

LOG = logging.getLogger(__name__)


class NsxvIpamDriver(common.NsxAbstractIpamDriver, common.NsxIpamBase):
    """IPAM Driver For NSX-V external & provider networks."""

    def _is_ext_or_provider_net(self, subnet_request):
        """Return True if the network of the request is external or
        provider network
        """
        network_id = subnet_request.network_id
        if network_id:
            network = self._fetch_network(self._context, network_id)
            if network.get(extnet_apidef.EXTERNAL):
                # external network
                return True
            if (validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)) or
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

    @property
    def _subnet_class(self):
        return NsxvIpamSubnet

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

    def delete_backend_pool(self, nsx_pool_id):
        try:
            self._vcns.delete_ipam_ip_pool(nsx_pool_id)
        except vc_exc.VcnsApiException as e:
            LOG.error("Failed to delete IPAM from backend: %s", e)
            # Continue anyway, since this subnet was already removed

    def update_backend_pool(self, subnet_request):
        # The NSX-v backend does not support changing the ip pool cidr
        # or gateway.
        # If this function is called - there is no need to update the backend
        pass


class NsxvIpamSubnet(common.NsxAbstractIpamSubnet, common.NsxIpamBase):
    """Manage IP addresses for the NSX-V IPAM driver."""

    def _get_vcns_error_code(self, e):
        """Get the error code out of VcnsApiException"""
        try:
            desc = et.fromstring(e.response)
            return int(desc.find('errorCode').text)
        except Exception:
            LOG.error('IPAM pool: Error code not present. %s',
                e.response)

    def backend_allocate(self, address_request):
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

    def backend_deallocate(self, address):
        try:
            self._vcns.release_ipam_ip_to_pool(self._nsx_pool_id, address)
        except vc_exc.VcnsApiException as e:
            LOG.error("NSX IPAM failed to free ip %(ip)s of subnet %(id)s:"
                      " %(e)s",
                      {'e': e.response,
                       'ip': address,
                       'id': self._subnet_id})
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self._subnet_id,
                ip_address=address)

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
