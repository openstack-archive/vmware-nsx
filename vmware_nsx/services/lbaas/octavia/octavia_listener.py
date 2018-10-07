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

import socket
import time

import eventlet

from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

from neutron_lbaas.db.loadbalancer import models

from vmware_nsx.services.lbaas.octavia import constants

LOG = logging.getLogger(__name__)


class NSXOctaviaListener(object):
    @log_helpers.log_method_call
    def __init__(self, loadbalancer=None, listener=None, pool=None,
                 member=None, healthmonitor=None, l7policy=None, l7rule=None):
        self._init_rpc_messaging()
        self._init_rpc_listener(healthmonitor, l7policy, l7rule, listener,
                                loadbalancer, member, pool)

    def _init_rpc_messaging(self):
        topic = constants.DRIVER_TO_OCTAVIA_TOPIC
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.client = messaging.RPCClient(transport, target)

    def _init_rpc_listener(self, healthmonitor, l7policy, l7rule, listener,
                           loadbalancer, member, pool):
        # Initialize RPC listener
        topic = constants.OCTAVIA_TO_DRIVER_TOPIC
        server = socket.gethostname()
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        self.endpoints = [NSXOctaviaListenerEndpoint(
            client=self.client, loadbalancer=loadbalancer, listener=listener,
            pool=pool, member=member, healthmonitor=healthmonitor,
            l7policy=l7policy, l7rule=l7rule)]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, self.endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class NSXOctaviaListenerEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self, client=None, loadbalancer=None, listener=None,
                 pool=None, member=None, healthmonitor=None, l7policy=None,
                 l7rule=None):

        self.client = client
        self.loadbalancer = loadbalancer
        self.listener = listener
        self.pool = pool
        self.member = member
        self.healthmonitor = healthmonitor
        self.l7policy = l7policy
        self.l7rule = l7rule

    def get_completor_func(self, obj_type, obj, delete=False):
        # return a method that will be called on success/failure completion
        def completor_func(success=True):
            LOG.debug("Octavia transaction completed. status %s",
                      'success' if success else 'failure')

            # calculate the provisioning and operating statuses
            main_prov_status = constants.ACTIVE
            parent_prov_status = constants.ACTIVE
            if not success:
                main_prov_status = constants.ERROR
                parent_prov_status = constants.ERROR
            elif delete:
                main_prov_status = constants.DELETED
            op_status = constants.ONLINE if success else constants.ERROR

            # add the status of the created/deleted/updated object
            status_dict = {
                obj_type: [{
                    'id': obj['id'],
                    constants.PROVISIONING_STATUS: main_prov_status,
                    constants.OPERATING_STATUS: op_status}]}

            # Get all its parents, and update their statuses as well
            loadbalancer_id = None
            listener_id = None
            pool_id = None
            policy_id = None
            if obj_type != constants.LOADBALANCERS:
                loadbalancer_id = None
                if obj.get('loadbalancer_id'):
                    loadbalancer_id = obj.get('loadbalancer_id')
                elif obj.get('pool'):
                    pool_id = obj['pool']['id']
                    loadbalancer_id = obj['pool']['loadbalancer_id']
                elif obj.get('listener'):
                    listener_id = obj['listener']['id']
                    loadbalancer_id = obj['listener']['loadbalancer_id']
                elif obj.get('policy') and obj['policy'].get('listener'):
                    policy_id = obj['policy']['id']
                    listener_id = obj['policy']['listener']['id']
                    loadbalancer_id = obj['policy']['listener'][
                        'loadbalancer_id']

                if loadbalancer_id:
                    status_dict[constants.LOADBALANCERS] = [{
                        'id': loadbalancer_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if listener_id:
                    status_dict[constants.LISTENERS] = [{
                        'id': listener_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if pool_id:
                    status_dict[constants.POOLS] = [{
                        'id': pool_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if policy_id:
                    status_dict[constants.L7POLICIES] = [{
                        'id': policy_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]

            kw = {'status': status_dict}
            self.client.cast({}, 'update_loadbalancer_status', **kw)

        return completor_func

    def update_listener_statistics(self, statistics):
        kw = {'statistics': statistics}
        self.client.cast({}, 'update_listener_statistics', **kw)

    @log_helpers.log_method_call
    def loadbalancer_create(self, ctxt, loadbalancer):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        self.loadbalancer.create(
            ctx, loadbalancer,
            self.get_completor_func(constants.LOADBALANCERS,
                                    loadbalancer))

    @log_helpers.log_method_call
    def loadbalancer_delete(self, ctxt, loadbalancer, cascade=False):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        # TODO(asarfaty): No support for cascade. It is blocked by the driver
        self.loadbalancer.delete(
            ctx, loadbalancer,
            self.get_completor_func(constants.LOADBALANCERS,
                                    loadbalancer,
                                    delete=True))

    @log_helpers.log_method_call
    def loadbalancer_update(self, ctxt, old_loadbalancer, new_loadbalancer):
        ctx = neutron_context.Context(None, old_loadbalancer['project_id'])
        self.loadbalancer.update(
            ctx, old_loadbalancer, new_loadbalancer,
            self.get_completor_func(constants.LOADBALANCERS,
                                    new_loadbalancer))

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, ctxt, listener, cert):
        ctx = neutron_context.Context(None, listener['project_id'])
        self.listener.create(ctx, listener,
                             self.get_completor_func(constants.LISTENERS,
                                                     listener),
                             certificate=cert)

    @log_helpers.log_method_call
    def listener_delete(self, ctxt, listener):
        ctx = neutron_context.Context(None, listener['project_id'])
        self.listener.delete(ctx, listener,
                             self.get_completor_func(constants.LISTENERS,
                                                     listener,
                                                     delete=True))

    @log_helpers.log_method_call
    def listener_update(self, ctxt, old_listener, new_listener, cert):
        ctx = neutron_context.Context(None, old_listener['project_id'])
        self.listener.update(ctx, old_listener, new_listener,
                             self.get_completor_func(constants.LISTENERS,
                                                     new_listener),
                             certificate=cert)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        self.pool.create(ctx, pool, self.get_completor_func(constants.POOLS,
                                                            pool))

    @log_helpers.log_method_call
    def pool_delete(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        self.pool.delete(ctx, pool, self.get_completor_func(constants.POOLS,
                                                            pool,
                                                            delete=True))

    @log_helpers.log_method_call
    def pool_update(self, ctxt, old_pool, new_pool):
        ctx = neutron_context.Context(None, old_pool['project_id'])
        self.pool.update(ctx, old_pool, new_pool,
                         self.get_completor_func(constants.POOLS, new_pool))

    # Member
    @log_helpers.log_method_call
    def member_create(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        self.member.create(ctx, member,
                           self.get_completor_func(constants.MEMBERS,
                                                   member))

    @log_helpers.log_method_call
    def member_delete(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        self.member.delete(ctx, member,
                           self.get_completor_func(constants.MEMBERS,
                                                   member,
                                                   delete=True))

    @log_helpers.log_method_call
    def member_update(self, ctxt, old_member, new_member):
        ctx = neutron_context.Context(None, old_member['project_id'])
        self.member.update(ctx, old_member, new_member,
                           self.get_completor_func(constants.MEMBERS,
                                                   new_member))

    # Health Monitor
    @log_helpers.log_method_call
    def healthmonitor_create(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        self.healthmonitor.create(ctx, healthmonitor,
                                  self.get_completor_func(
                                      constants.HEALTHMONITORS, healthmonitor))

    @log_helpers.log_method_call
    def healthmonitor_delete(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        self.healthmonitor.delete(ctx, healthmonitor,
                                  self.get_completor_func(
                                      constants.HEALTHMONITORS, healthmonitor,
                                      delete=True))

    @log_helpers.log_method_call
    def healthmonitor_update(self, ctxt, old_healthmonitor, new_healthmonitor):
        ctx = neutron_context.Context(None, old_healthmonitor['project_id'])
        self.healthmonitor.update(ctx, old_healthmonitor, new_healthmonitor,
                                  self.get_completor_func(
                                      constants.HEALTHMONITORS,
                                      new_healthmonitor))

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        self.l7policy.create(ctx, l7policy,
                             self.get_completor_func(constants.L7POLICIES,
                                                     l7policy))

    @log_helpers.log_method_call
    def l7policy_delete(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        self.l7policy.delete(ctx, l7policy,
                             self.get_completor_func(constants.L7POLICIES,
                                                     l7policy,
                                                     delete=True))

    @log_helpers.log_method_call
    def l7policy_update(self, ctxt, old_l7policy, new_l7policy):
        ctx = neutron_context.Context(None, old_l7policy['project_id'])
        self.l7policy.update(ctx, old_l7policy, new_l7policy,
                             self.get_completor_func(constants.L7POLICIES,
                                                     new_l7policy))

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        self.l7rule.create(ctx, l7rule,
                           self.get_completor_func(constants.L7RULES, l7rule))

    @log_helpers.log_method_call
    def l7rule_delete(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        self.l7rule.delete(ctx, l7rule,
                           self.get_completor_func(constants.L7RULES,
                                                   l7rule,
                                                   delete=True))

    @log_helpers.log_method_call
    def l7rule_update(self, ctxt, old_l7rule, new_l7rule):
        ctx = neutron_context.Context(None, old_l7rule['project_id'])
        self.l7rule.update(ctx, old_l7rule, new_l7rule,
                           self.get_completor_func(constants.L7RULES,
                                                   new_l7rule))


class NSXOctaviaStatisticsCollector(object):
    def __init__(self, core_plugin, listener_stats_getter):
        self.core_plugin = core_plugin
        self.listener_stats_getter = listener_stats_getter
        if cfg.CONF.octavia_stats_interval:
            eventlet.spawn_n(self.thread_runner,
                             cfg.CONF.octavia_stats_interval)

    @log_helpers.log_method_call
    def thread_runner(self, interval):
        while True:
            time.sleep(interval)
            self.collect()

    def _get_nl_loadbalancers(self, context):
        """Getting the list of neutron-lbaas loadbalancers

        This is done directly from the neutron-lbaas DB to also support the
        case that the plugin is currently unavailable, but entries already
        exist on the DB.
        """
        nl_loadbalancers = context.session.query(models.LoadBalancer).all()
        return [lb.id for lb in nl_loadbalancers]

    @log_helpers.log_method_call
    def collect(self):
        if not self.core_plugin.octavia_listener:
            return

        endpoint = self.core_plugin.octavia_listener.endpoints[0]
        context = neutron_context.get_admin_context()

        # get the statistics of all the Octavia loadbalancers/listeners while
        # ignoring the neutron-lbaas loadbalancers.
        # Note(asarfaty): The Octavia plugin/DB is unavailable from the
        # neutron context, so there is no option to query the Octavia DB for
        # the relevant loadbalancers.
        nl_loadbalancers = self._get_nl_loadbalancers(context)
        listeners_stats = self.listener_stats_getter(
            context, self.core_plugin, ignore_list=nl_loadbalancers)
        if not listeners_stats:
            # Avoid sending empty stats
            return
        stats = {'listeners': listeners_stats}
        endpoint.update_listener_statistics(stats)
