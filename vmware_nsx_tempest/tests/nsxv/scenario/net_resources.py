# Copyright 2015 OpenStack Foundation
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
#
# This module inherents from resources module and enhances router functions
# and block subnet's add_to/delete_from_router so it is more similar to CLI.

from tempest.scenario import network_resources as n_resources


DELETABLE_CLASS_DEF = """class %(cls_name)s(n_resources.%(cls_name)s):
    pass
"""
IGNORE_LIST = ['DeletableSubnet', 'DeletableRouter']


# inhere Deletable<Class> from parent module
for cls_name in [x for x in dir(n_resources)
                 if x.startswith('Deletable') and x not in IGNORE_LIST]:
    class_def = DELETABLE_CLASS_DEF % dict(cls_name=cls_name)
    exec class_def


# Add/mod methods so we can use it while sustain original functions.
MSG_BLOCK_BY_ADMIN = "Block %s as router might be owned by ADMIN. " \
                     "Use DeletableRouter instead."


class DeletableSubnet(n_resources.DeletableSubnet):

    def __init__(self, *args, **kwargs):
        super(DeletableSubnet, self).__init__(*args, **kwargs)

    def add_to_router(self, router_id):
        raise Exception(MSG_BLOCK_BY_ADMIN % "add_to_router()")

    def delete_from_router(self, router_id):
        raise Exception(MSG_BLOCK_BY_ADMIN % "delete_from_router()")


# DeletableSubnet should not deal with router which when owned by ADMIN
# will raise privilege issue. Always let the router deals with interfaces.
class DeletableRouter(n_resources.DeletableRouter):
    def __init__(self, *args, **kwargs):
        super(DeletableRouter, self).__init__(*args, **kwargs)
        self._subnets = set()

    def set_gateway(self, network_id):
        return self.client.update_router(
            self.id,
            external_gateway_info=dict(network_id=network_id))

    def unset_gateway(self):
        return self.client.update_router(
            self.id,
            external_gateway_info=dict())

    def add_subnet(self, subnet):
        return self.add_interface(subnet)

    def add_interface(self, subnet):
        # should not let subnet add interface to router as
        # the router might be crated by admin.
        try:
            self.client.add_router_interface(
                self.id, subnet_id=subnet.id)
        except Exception:
            x_method(self.client, 'add_router_interface_with_subnet_id',
                     self.id, subnet_id=subnet.id)
        self._subnets.add(subnet)

    def delete_subnet(self, subnet):
        return self.delete_interface(subnet)

    def delete_interface(self, subnet):
        try:
            self.client.remove_router_interface(
                self.id, subnet_id=subnet.id)
        except Exception:
            x_method(self.client, 'remove_router_interface_with_subnet_id',
                     self.id, subnet_id=subnet.id)
        self._subnets.remove(subnet)

    def update_extra_routes(self, nexthop, destination):
        return self.client.update_extra_routes(self.id, nexthop, destination)

    # to-be-fixed by https://bugs.launchpad.net/tempest/+bug/1468600
    def update_extra_routes_future(self, routes):
        return self.client.update_extra_routes(self.id, routes)

    def delete_extra_routes(self):
        return self.client.delete_extra_routes(self.id)

    def delete(self):
        try:
            self.delete_extra_routes()
        except Exception:
            pass
        self.unset_gateway()
        for subnet in self._subnets.copy():
            self.delete_interface(subnet)
        super(DeletableRouter, self).delete()


# Workaround solution
def x_method(target_obj, method_name, *args, **kwargs):
    _method = getattr(target_obj, method_name, None)
    if _method is None:
        raise Exception("Method[%s] is not defined at instance[%s]" %
                        (method_name, str(target_obj)))
    results = _method(*args, **kwargs)
    return results
