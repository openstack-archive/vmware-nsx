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

import time

from oslo_config import cfg
from oslo_log import log as logging

from neutron.db import common_db_mixin as common_db
from neutron_lib import context as neutron_context
from neutron_lib.plugins import directory

from vmware_nsx.common import config
from vmware_nsx import plugin
from vmware_nsx.plugins.nsx_v.vshield import vcns

LOG = logging.getLogger(__name__)


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


class NsxVPluginWrapper(plugin.NsxVPlugin):

    def __init__(self):
        config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
        super(NsxVPluginWrapper, self).__init__()
        # Make this the core plugin
        directory.add_plugin('CORE', self)
        # finish the plugin initialization (md-proxy)
        self.init_complete(0, 0, 0)

    def _start_rpc_listeners(self):
        pass

    def _extend_get_network_dict_provider(self, context, net):
        self._extend_network_dict_provider(context, net)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def count_spawn_jobs(self):
        # check if there are any spawn jobs running
        return self.edge_manager._get_worker_pool().running()

    # Define enter & exit to be used in with statements
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        """Wait until no more jobs are pending

        We want to wait until all spawn edge creation are done, or else the
        edges might be in PERNDING_CREATE state in the nsx DB
        """
        if not self.count_spawn_jobs():
            return

        LOG.warning("Waiting for plugin jobs to finish properly...")
        sleep_time = 1
        print_time = 20
        max_loop = 600
        for print_index in range(1, max_loop):
            n_jobs = self.count_spawn_jobs()
            if n_jobs > 0:
                if (print_index % print_time) == 0:
                    LOG.warning("Still Waiting on %(jobs)s "
                                "job%(plural)s",
                                {'jobs': n_jobs,
                                 'plural': 's' if n_jobs > 1 else ''})
                time.sleep(sleep_time)
            else:
                LOG.warning("Done.")
                return

        LOG.warning("Sorry. Waited for too long. Some jobs are still "
                    "running.")


def get_nsxv_backend_edges():
    """Get a list of all the backend edges and some of their attributes
    """
    nsxv = get_nsxv_client()
    edges = nsxv.get_edges()
    backend_edges = []
    for edge in edges:
        # get all the relevant backend information for this edge
        edge_data = {
            'id': edge.get('id'),
            'name': edge.get('name'),
            'size': edge['appliancesSummary'].get(
                'applianceSize') if edge.get('appliancesSummary') else None,
            'type': edge.get('edgeType')
        }
        backend_edges.append(edge_data)
    return backend_edges


def get_edge_syslog_info(edge_id):
    """Get syslog information for specific edge id"""

    nsxv = get_nsxv_client()
    syslog_info = nsxv.get_edge_syslog(edge_id)[1]
    if not syslog_info['enabled']:
        return 'Disabled'

    output = ""
    if 'protocol' in syslog_info:
        output += syslog_info['protocol']
    if 'serverAddresses' in syslog_info:
        for server_address in syslog_info['serverAddresses']['ipAddress']:
            output += "\n" + server_address

    return output
