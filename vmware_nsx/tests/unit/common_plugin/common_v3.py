# Copyright 2018 VMware, Inc.
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

import contextlib

import decorator

from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin


class FixExternalNetBaseTest(object):
    """Base class providing utilities for handling tests which require updating
    a network to be external, which is not supported for the NSX-v3 and NSX-P
    plugins.
    """
    def setUp(self, *args, **kwargs):
        self.original_subnet = self.subnet
        self.original_create_subnet = self._create_subnet
        self.original_network = self.network
        self.subnet_calls = []
        super(FixExternalNetBaseTest, self).setUp(*args, **kwargs)

    def _set_net_external(self, net_id):
        # This action is not supported by the V3 plugin
        pass

    def _create_external_network(self):
        data = {'network': {'name': 'net1',
                            'router:external': 'True',
                            'tenant_id': 'tenant_one',
                            'provider:physical_network': 'stam'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        return network

    def external_subnet(self, network=None, **kwargs):
        # External subnet ,ust have dhcp disabled
        kwargs['enable_dhcp'] = False
        if network:
            return self.original_subnet(network=network, **kwargs)
        ext_net = self._create_external_network()
        return self.original_subnet(network=ext_net, **kwargs)

    def create_external_subnet(self, *args, **kwargs):
        kwargs['enable_dhcp'] = False
        return super(FixExternalNetBaseTest, self)._create_subnet(
            *args, **kwargs)

    def no_dhcp_subnet(self, *args, **kwargs):
        if 'enable_dhcp' in kwargs:
            return self.original_subnet(*args, **kwargs)
        return self.original_subnet(*args, enable_dhcp=False, **kwargs)

    def external_subnet_by_list(self, *args, **kwargs):
        if len(self.subnet_calls) > 0:
            result = self.subnet_calls[0](*args, **kwargs)
            del self.subnet_calls[0]
        else:
            # back to normal
            self.subnet = self.original_subnet
            result = self.subnet(*args, **kwargs)
        return result

    @contextlib.contextmanager
    def floatingip_with_assoc(self, port_id=None, fmt=None, fixed_ip=None,
                              public_cidr='11.0.0.0/24', set_context=False,
                              tenant_id=None, **kwargs):
        # Override super implementation to avoid changing the network to
        # external after creation
        with self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net, cidr=public_cidr,
                        set_context=set_context,
                        tenant_id=tenant_id,
                        enable_dhcp=False) as public_sub:
            private_port = None
            if port_id:
                private_port = self._show('ports', port_id)
            with test_plugin.optional_ctx(
                    private_port, self.port,
                    set_context=set_context,
                    tenant_id=tenant_id) as private_port:
                with self.router(set_context=set_context,
                                 tenant_id=tenant_id) as r:
                    sid = private_port['port']['fixed_ips'][0]['subnet_id']
                    private_sub = {'subnet': {'id': sid}}
                    floatingip = None

                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    floatingip = self._make_floatingip(
                        fmt or self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'],
                        fixed_ip=fixed_ip,
                        tenant_id=tenant_id,
                        set_context=set_context,
                        **kwargs)
                    yield floatingip

                    if floatingip:
                        self._delete('floatingips',
                                     floatingip['floatingip']['id'])

    @contextlib.contextmanager
    def floatingip_no_assoc(self, private_sub, fmt=None,
                            set_context=False, flavor_id=None, **kwargs):
        # override super code to create an external subnet in advanced
        with self.external_subnet(cidr='12.0.0.0/24') as public_sub:
            with self.floatingip_no_assoc_with_public_sub(
                private_sub, fmt, set_context, public_sub,
                flavor_id, **kwargs) as (f, r):
                # Yield only the floating ip object
                yield f


# Override subnet/network creation in some tests to create external
# networks immediately instead of updating it post creation, which the
# v3 plugin does not support
@decorator.decorator
def with_external_subnet(f, *args, **kwargs):
    obj = args[0]
    obj.subnet = obj.external_subnet
    result = f(*args, **kwargs)
    obj.subnet = obj.original_subnet
    return result


def init_subnet_calls(self, n):
    self.subnet_calls = []
    for i in range(0, n - 1):
        self.subnet_calls.append(self.subnet)
    self.subnet_calls.append(self.external_subnet)


def call_with_subnet_calls(self, f, *args, **kwargs):
    self.subnet = self.external_subnet_by_list
    result = f(*args, **kwargs)
    self.subnet = self.original_subnet
    return result


@decorator.decorator
def with_external_subnet_once(f, *args, **kwargs):
    obj = args[0]
    init_subnet_calls(obj, 1)
    return call_with_subnet_calls(obj, f, *args, **kwargs)


@decorator.decorator
def with_external_subnet_second_time(f, *args, **kwargs):
    obj = args[0]
    init_subnet_calls(obj, 2)
    return call_with_subnet_calls(obj, f, *args, **kwargs)


@decorator.decorator
def with_external_subnet_third_time(f, *args, **kwargs):
    obj = args[0]
    init_subnet_calls(obj, 3)
    return call_with_subnet_calls(obj, f, *args, **kwargs)


@decorator.decorator
def with_external_network(f, *args, **kwargs):
    obj = args[0]
    obj.network = obj.external_network
    obj.subnet = obj.external_subnet
    obj._create_subnet = obj.create_external_subnet
    result = f(*args, **kwargs)
    obj._create_subnet = obj.original_create_subnet
    obj.subnet = obj.original_subnet
    obj.network = obj.original_network
    return result


# Override subnet creation in some tests to create a subnet with dhcp
# disabled
@decorator.decorator
def with_no_dhcp_subnet(f, *args, **kwargs):
    obj = args[0]
    obj.subnet = obj.no_dhcp_subnet
    result = f(*args, **kwargs)
    obj.subnet = obj.original_subnet
    return result
