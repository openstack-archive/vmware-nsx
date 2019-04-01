# Copyright 2019 VMware, Inc.
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
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import lb_const


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
