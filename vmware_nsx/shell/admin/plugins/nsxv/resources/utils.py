# Copyright 2015 VMware, Inc.  All rights reserved.
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

from neutron import context as neutron_context
from neutron.db import common_db_mixin as common_db
from vmware_nsx.plugins.nsx_v.vshield import vcns


def get_nsxv_client():
    return vcns.Vcns(
        address=cfg.CONF.nsxv.manager_uri,
        user=cfg.CONF.nsxv.user,
        password=cfg.CONF.nsxv.password,
        ca_file=cfg.CONF.nsxv.ca_file,
        insecure=cfg.CONF.nsxv.insecure)


class NeutronDbClient(common_db.CommonDbMixin):
    def __init__(self):
        super(NeutronDbClient, self)
        self.context = neutron_context.get_admin_context()
