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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import load_balancer as nsxlib_lb
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgePoolManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgePoolManagerFromDict, self).__init__()

    def _get_pool_kwargs(self, name=None, tags=None, algorithm=None,
                         description=None):
        kwargs = {}
        if name:
            kwargs['display_name'] = name
        if tags:
            kwargs['tags'] = tags
        if algorithm:
            kwargs['algorithm'] = algorithm
        if description:
            kwargs['description'] = description
        kwargs['snat_translation'] = {'type': "LbSnatAutoMap"}
        return kwargs

    def _build_persistence_profile_tags(self, pool_tags, listener):
        tags = pool_tags[:]
        tags.append({
            'scope': 'os-lbaas-lb-name',
            'tag': listener['loadbalancer']['name'][:utils.MAX_TAG_LEN]})
        tags.append({
            'scope': 'os-lbaas-lb-id',
            'tag': listener['loadbalancer_id']})
        tags.append({
            'scope': 'os-lbaas-listener-id',
            'tag': listener['id']})
        return tags

    def _validate_session_persistence(self, pool, listener, completor,
                                      old_pool=None):
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

    def _setup_session_persistence(self, pool, pool_tags,
                                   listener, vs_data):
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
                'tags': self._build_persistence_profile_tags(
                    pool_tags, listener)
            }
            if cookie_name:
                pp_kwargs['cookie_name'] = cookie_name
                pp_kwargs['cookie_mode'] = cookie_mode

        pp_client = self.core_plugin.nsxlib.load_balancer.persistence_profile
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
                return (None, functools.partial(self._remove_persistence,
                                                vs_data))
        elif pers_type:
            # Create persistence profile
            pp_data = pp_client.create(**pp_kwargs)
            LOG.debug("Creaed persistence profile %(profile_id)s for "
                      "listener %(listener_id)s with pool %(pool_id)s",
                      {'profile_id': pp_data['id'],
                       'listener_id': listener['id'],
                       'pool_id': pool['id']})
            return pp_data['id'], None

    def _remove_persistence(self, vs_data):
        pp_client = self.core_plugin.nsxlib.load_balancer.persistence_profile
        persistence_profile_id = vs_data.get('persistence_profile_id')
        if persistence_profile_id:
            pp_client.delete(persistence_profile_id)

    def _process_vs_update(self, context, pool, listener,
                           nsx_pool_id, nsx_vs_id, completor):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        try:
            # Process pool persistence profile and
            # create/update/delete profile for virtual server
            vs_data = vs_client.get(nsx_vs_id)
            if nsx_pool_id:
                (persistence_profile_id,
                 post_process_func) = self._setup_session_persistence(
                    pool, self._get_pool_tags(context, pool),
                    listener, vs_data)
            else:
                post_process_func = functools.partial(
                    self._remove_persistence, vs_data)
                persistence_profile_id = None
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error("Failed to configure session persistence "
                          "profile for pool %(pool_id)s",
                          {'pool_id': pool['id']})
        try:
            # Update persistence profile and pool on virtual server
            vs_client.update(nsx_vs_id, pool_id=nsx_pool_id,
                             persistence_profile_id=persistence_profile_id)
            LOG.debug("Updated NSX virtual server %(vs_id)s with "
                      "pool %(pool_id)s and persistence profile %(prof)s",
                      {'vs_id': nsx_vs_id, 'pool_id': nsx_pool_id,
                       'prof': persistence_profile_id})
            if post_process_func:
                post_process_func()
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to attach pool %s to virtual '
                          'server %s', nsx_pool_id, nsx_vs_id)

    def _get_pool_tags(self, context, pool):
        return lb_utils.get_tags(self.core_plugin, pool['id'],
                                 lb_const.LB_POOL_TYPE, pool['tenant_id'],
                                 context.project_name)

    def create(self, context, pool, completor):
        lb_id = pool['loadbalancer_id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        pool_name = utils.get_name_and_uuid(pool['name'] or 'pool', pool['id'])
        tags = self._get_pool_tags(context, pool)
        description = pool.get('description')
        lb_algorithm = lb_const.LB_POOL_ALGORITHM_MAP.get(pool['lb_algorithm'])
        # NOTE(salv-orlando): Guard against accidental compat breakages
        try:
            listener = pool['listener'] or pool['listeners'][0]
        except IndexError:
            # If listeners is an empty list we hit this exception
            listener = None
        # Perform additional validation for session persistence before
        # creating resources in the backend
        self._validate_session_persistence(pool, listener, completor)
        try:
            kwargs = self._get_pool_kwargs(pool_name, tags, lb_algorithm,
                                           description)
            lb_pool = pool_client.create(**kwargs)
            nsx_db.add_nsx_lbaas_pool_binding(
                context.session, lb_id, pool['id'], lb_pool['id'])
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to create pool on NSX backend: %(pool)s') %
                   {'pool': pool['id']})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        # The pool object can be created with either --listener or
        # --loadbalancer option. If listener is present, the virtual server
        # will be updated with the pool. Otherwise, just return. The binding
        # will be added later when the pool is associated with layer7 rule.
        # FIXME(salv-orlando): This two-step process can leave a zombie pool on
        # NSX if the VS update operation fails
        if listener:
            listener_id = listener['id']
            binding = nsx_db.get_nsx_lbaas_listener_binding(
                context.session, lb_id, listener_id)
            if binding:
                vs_id = binding['lb_vs_id']
                self._process_vs_update(context, pool, listener,
                                        lb_pool['id'], vs_id, completor)
                nsx_db.update_nsx_lbaas_pool_binding(
                    context.session, lb_id, pool['id'], vs_id)
            else:
                msg = (_("Couldn't find binding on the listener: %s") %
                       listener['id'])
                raise nsx_exc.NsxPluginException(err_msg=msg)
        completor(success=True)

    def update(self, context, old_pool, new_pool, completor):
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        pool_name = None
        tags = None
        lb_algorithm = None
        description = None
        if new_pool['name'] != old_pool['name']:
            pool_name = utils.get_name_and_uuid(new_pool['name'] or 'pool',
                                                new_pool['id'])
            tags = self._get_pool_tags(context, new_pool)
        if new_pool['lb_algorithm'] != old_pool['lb_algorithm']:
            lb_algorithm = lb_const.LB_POOL_ALGORITHM_MAP.get(
                new_pool['lb_algorithm'])
        if new_pool.get('description') != old_pool.get('description'):
            description = new_pool['description']
        binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, old_pool['loadbalancer_id'], old_pool['id'])
        if not binding:
            msg = (_('Cannot find pool %(pool)s binding on NSX db '
                     'mapping') % {'pool': old_pool['id']})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)
        # NOTE(salv-orlando): Guard against accidental compat breakages
        try:
            listener = new_pool['listener'] or new_pool['listeners'][0]
        except IndexError:
            # If listeners is an empty list we hit this exception
            listener = None
            # Perform additional validation for session persistence before
            # operating on resources in the backend
        self._validate_session_persistence(new_pool, listener, completor,
                                           old_pool=old_pool)

        try:
            lb_pool_id = binding['lb_pool_id']
            kwargs = self._get_pool_kwargs(pool_name, tags, lb_algorithm,
                                           description)
            pool_client.update(lb_pool_id, **kwargs)
            if (listener and new_pool['session_persistence'] !=
                old_pool['session_persistence']):
                self._process_vs_update(context, new_pool, listener,
                                        lb_pool_id, binding['lb_vs_id'],
                                        completor)
            completor(success=True)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update pool %(pool)s with '
                          'error %(error)s',
                          {'pool': old_pool['id'], 'error': e})

    def delete(self, context, pool, completor):
        lb_id = pool['loadbalancer_id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool

        binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool['id'])
        if binding:
            vs_id = binding.get('lb_vs_id')
            lb_pool_id = binding.get('lb_pool_id')

            if vs_id:
                # NOTE(salv-orlando): Guard against accidental compat breakages
                try:
                    listener = pool['listener'] or pool['listeners'][0]
                except IndexError:
                    # If listeners is an empty list we hit this exception
                    listener = None
                if listener:
                    self._process_vs_update(context, pool, listener,
                                            None, vs_id, completor)
            try:
                pool_client.delete(lb_pool_id)
            except nsxlib_exc.ResourceNotFound:
                pass
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = (_('Failed to delete lb pool from nsx: %(pool)s') %
                       {'pool': lb_pool_id})
                raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)
            nsx_db.delete_nsx_lbaas_pool_binding(context.session,
                                                 lb_id, pool['id'])

        completor(success=True)
