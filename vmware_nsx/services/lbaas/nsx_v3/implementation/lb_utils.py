# Copyright 2017 VMware, Inc.
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

import functools

from neutron.db import l3_db
from neutron.services.flavors import flavors_plugin
from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import lb_const
from vmware_nsxlib.v3 import load_balancer as nsxlib_lb
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)
ADV_RULE_NAME = 'LB external VIP advertisement'
NO_ROUTER_ID = 'NO ROUTER'


@log_helpers.log_method_call
def get_tags(plugin, resource_id, resource_type, project_id, project_name):
    resource = {'project_id': project_id,
                'id': resource_id}
    tags = plugin.nsxlib.build_v3_tags_payload(
        resource, resource_type=resource_type,
        project_name=project_name)
    return tags


@log_helpers.log_method_call
def get_network_from_subnet(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    if subnet:
        return plugin.get_network(context, subnet['network_id'])


@log_helpers.log_method_call
def get_router_from_network(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet['network_id']
    port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                    'network_id': [network_id]}
    ports = plugin.get_ports(context, filters=port_filters)
    if ports:
        router = plugin.get_router(context, ports[0]['device_id'])
        if router.get('external_gateway_info'):
            return router['id']


@log_helpers.log_method_call
def get_lb_flavor_size(flavor_plugin, context, flavor_id):
    if not flavor_id:
        return lb_const.DEFAULT_LB_SIZE
    else:
        flavor = flavors_plugin.FlavorsPlugin.get_flavor(
            flavor_plugin, context, flavor_id)
        flavor_size = flavor['name']
        if flavor_size in lb_const.LB_FLAVOR_SIZES:
            return flavor_size.upper()
        else:
            err_msg = (_("Invalid flavor size %(flavor)s, only 'small', "
                         "'medium', or 'large' are supported") %
                       {'flavor': flavor_size})
            raise n_exc.InvalidInput(error_message=err_msg)


@log_helpers.log_method_call
def validate_lb_subnet(context, plugin, subnet_id):
    '''Validate LB subnet before creating loadbalancer on it.

    To create a loadbalancer, the network has to be either an external
    network or private network that connects to a tenant router. The
    tenant router needs to connect to gateway. It will throw
    exception if the network doesn't meet this requirement.

    :param context: context
    :param plugin: core plugin
    :param subnet_id: loadbalancer's subnet id
    :return: True if subnet meet requirement, otherwise return False
    '''
    network = get_network_from_subnet(context, plugin, subnet_id)
    valid_router = get_router_from_network(
        context, plugin, subnet_id)
    if network.get('router:external') or valid_router:
        return True
    else:
        return False


@log_helpers.log_method_call
def validate_lb_member_subnet(context, plugin, subnet_id, lb):
    '''Validate LB member subnet before creating a member.

    The member subnet should belong to an external network or be connected
    to the same T1 router as the Lb vip.
    It will throw exception if the subnet doesn't meet this requirement.

    :param context: context
    :param plugin: core plugin
    :param subnet_id: loadbalancer's subnet id
    :return: True if subnet meet requirement, otherwise return False
    '''
    network = get_network_from_subnet(context, plugin, subnet_id)
    if network.get('router:external'):
        return True
    member_router_id = get_router_from_network(
        context, plugin, subnet_id)
    lb_router_id = get_router_from_network(
        context, plugin, lb['vip_subnet_id'])
    if lb_router_id:
        # Lb on non-external network. member must be on the same router
        if lb_router_id == member_router_id:
            return True
        else:
            return False
    else:
        # LB on external network. member subnet must have a router
        if member_router_id:
            return True
        else:
            return False


@log_helpers.log_method_call
def get_rule_match_conditions(policy):
    match_conditions = []
    # values in rule have already been validated in LBaaS API,
    # we won't need to valid anymore in driver, and just get
    # the LB rule mapping from the dict.
    for rule in policy['rules']:
        match_type = lb_const.LB_RULE_MATCH_TYPE[rule['compare_type']]
        if rule['type'] == lb_const.L7_RULE_TYPE_COOKIE:
            header_value = rule['key'] + '=' + rule['value']
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Cookie',
                 'header_value': header_value})
        elif rule['type'] == lb_const.L7_RULE_TYPE_FILE_TYPE:
            match_conditions.append(
                {'type': 'LbHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': '*.' + rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HEADER:
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': rule['key'],
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HOST_NAME:
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Host',
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_PATH:
            match_conditions.append(
                {'type': 'LbHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': rule['value']})
        else:
            msg = (_('l7rule type %(type)s is not supported in LBaaS') %
                   {'type': rule['type']})
            raise n_exc.BadRequest(resource='lbaas-l7rule', msg=msg)
    return match_conditions


@log_helpers.log_method_call
def get_rule_actions(context, l7policy):
    lb_id = l7policy['listener']['loadbalancer_id']
    if l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
        pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, l7policy['redirect_pool_id'])
        if pool_binding:
            lb_pool_id = pool_binding['lb_pool_id']
            actions = [{'type': lb_const.LB_SELECT_POOL_ACTION,
                        'pool_id': lb_pool_id}]
        else:
            msg = _('Failed to get LB pool binding from nsx db')
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
        actions = [{'type': lb_const.LB_HTTP_REDIRECT_ACTION,
                    'redirect_status': lb_const.LB_HTTP_REDIRECT_STATUS,
                    'redirect_url': l7policy['redirect_url']}]
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REJECT:
        actions = [{'type': lb_const.LB_REJECT_ACTION,
                    'reply_status': lb_const.LB_HTTP_REJECT_STATUS}]
    else:
        msg = (_('Invalid l7policy action: %(action)s') %
               {'action': l7policy['action']})
        raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                               msg=msg)
    return actions


@log_helpers.log_method_call
def convert_l7policy_to_lb_rule(context, policy):
    return {
        'match_conditions': get_rule_match_conditions(policy),
        'actions': get_rule_actions(context, policy),
        'phase': lb_const.LB_RULE_HTTP_FORWARDING,
        'match_strategy': 'ALL'
    }


@log_helpers.log_method_call
def remove_rule_from_policy(rule):
    l7rules = rule['policy']['rules']
    rule['policy']['rules'] = [r for r in l7rules if r['id'] != rule['id']]


@log_helpers.log_method_call
def update_rule_in_policy(rule):
    remove_rule_from_policy(rule)
    rule['policy']['rules'].append(rule)


@log_helpers.log_method_call
def update_router_lb_vip_advertisement(context, core_plugin, router,
                                       nsx_router_id):
    # Add a rule to advertise external vips on the router
    external_subnets = core_plugin._find_router_gw_subnets(
        context.elevated(), router)
    external_cidrs = [s['cidr'] for s in external_subnets]
    if external_cidrs:
        adv_rule = {
            'display_name': ADV_RULE_NAME,
            'action': nsx_constants.FW_ACTION_ALLOW,
            'networks': external_cidrs,
            'rule_filter': {'prefix_operator': 'GE',
                            'match_route_types': ['T1_LB_VIP']}}
        core_plugin.nsxlib.logical_router.update_advertisement_rules(
            nsx_router_id, [adv_rule], name_prefix=ADV_RULE_NAME)


@log_helpers.log_method_call
def validate_session_persistence(pool, listener, completor, old_pool=None):
    sp = pool.get('session_persistence')
    if not listener or not sp:
        # safety first!
        return
    # L4 listeners only allow source IP persistence
    if (listener['protocol'] == lb_const.LB_PROTOCOL_TCP and
        sp['type'] != lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP):
        completor(success=False)
        msg = (_("Invalid session persistence type %(sp_type)s for "
                 "pool on listener %(lst_id)s with %(proto)s protocol") %
               {'sp_type': sp['type'],
                'lst_id': listener['id'],
                'proto': listener['protocol']})
        raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)
    # Cannot switch (yet) on update from source IP to cookie based, and
    # vice versa
    cookie_pers_types = (lb_const.LB_SESSION_PERSISTENCE_HTTP_COOKIE,
                         lb_const.LB_SESSION_PERSISTENCE_APP_COOKIE)
    if old_pool:
        oldsp = old_pool.get('session_persistence')
        if not oldsp:
            return
        if ((sp['type'] == lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP and
             oldsp['type'] in cookie_pers_types) or
            (sp['type'] in cookie_pers_types and
             oldsp['type'] == lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP)):
            completor(success=False)
            msg = (_("Cannot update session persistence type to "
                     "%(sp_type)s for pool on listener %(lst_id)s "
                     "from %(old_sp_type)s") %
                   {'sp_type': sp['type'],
                    'lst_id': listener['id'],
                    'old_sp_type': oldsp['type']})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)


@log_helpers.log_method_call
def delete_persistence_profile(nsxlib, persistence_profile_id):
    if persistence_profile_id:
        nsxlib.load_balancer.persistence_profile.delete(persistence_profile_id)


@log_helpers.log_method_call
def build_persistence_profile_tags(pool_tags, listener):
    tags = pool_tags[:]
    # With octavia loadbalancer name might not be among data passed
    # down to the driver
    lb_data = listener.get('loadbalancer')
    if lb_data:
        tags.append({
            'scope': 'os-lbaas-lb-name',
            'tag': lb_data['name'][:utils.MAX_TAG_LEN]})
    tags.append({
        'scope': 'os-lbaas-lb-id',
        'tag': listener['loadbalancer_id']})
    tags.append({
        'scope': 'os-lbaas-listener-id',
        'tag': listener['id']})
    return tags


def get_pool_tags(context, core_plugin, pool):
    return get_tags(core_plugin, pool['id'],
                    lb_const.LB_POOL_TYPE, pool['tenant_id'],
                    context.project_name)


@log_helpers.log_method_call
def setup_session_persistence(nsxlib, pool, pool_tags, listener, vs_data):
    sp = pool.get('session_persistence')
    pers_type = None
    cookie_name = None
    cookie_mode = None
    if not sp:
        LOG.debug("No session persistence info for pool %s", pool['id'])
    elif sp['type'] == lb_const.LB_SESSION_PERSISTENCE_HTTP_COOKIE:
        pers_type = nsxlib_lb.PersistenceProfileTypes.COOKIE
        cookie_name = sp.get('cookie_name')
        if not cookie_name:
            cookie_name = lb_const.SESSION_PERSISTENCE_DEFAULT_COOKIE_NAME
        cookie_mode = "INSERT"
    elif sp['type'] == lb_const.LB_SESSION_PERSISTENCE_APP_COOKIE:
        pers_type = nsxlib_lb.PersistenceProfileTypes.COOKIE
        # In this case cookie name is mandatory
        cookie_name = sp['cookie_name']
        cookie_mode = "REWRITE"
    else:
        pers_type = nsxlib_lb.PersistenceProfileTypes.SOURCE_IP

    if pers_type:
        # There is a profile to create or update
        pp_kwargs = {
            'resource_type': pers_type,
            'display_name': "persistence_%s" % utils.get_name_and_uuid(
                pool['name'] or 'pool', pool['id'], maxlen=235),
            'tags': build_persistence_profile_tags(pool_tags, listener)
        }
        if cookie_name:
            pp_kwargs['cookie_name'] = cookie_name
            pp_kwargs['cookie_mode'] = cookie_mode

    pp_client = nsxlib.load_balancer.persistence_profile
    persistence_profile_id = vs_data.get('persistence_profile_id')
    if persistence_profile_id:
        # NOTE: removal of the persistence profile must be executed
        # after the virtual server has been updated
        if pers_type:
            # Update existing profile
            LOG.debug("Updating persistence profile %(profile_id)s for "
                      "listener %(listener_id)s with pool %(pool_id)s",
                      {'profile_id': persistence_profile_id,
                       'listener_id': listener['id'],
                       'pool_id': pool['id']})
            pp_client.update(persistence_profile_id, **pp_kwargs)
            return persistence_profile_id, None
        else:
            # Prepare removal of persistence profile
            return (None, functools.partial(delete_persistence_profile,
                                            nsxlib, persistence_profile_id))
    elif pers_type:
        # Create persistence profile
        pp_data = pp_client.create(**pp_kwargs)
        LOG.debug("Created persistence profile %(profile_id)s for "
                  "listener %(listener_id)s with pool %(pool_id)s",
                  {'profile_id': pp_data['id'],
                   'listener_id': listener['id'],
                   'pool_id': pool['id']})
        return pp_data['id'], None
    return None, None
