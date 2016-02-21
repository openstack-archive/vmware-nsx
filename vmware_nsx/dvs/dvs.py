# Copyright 2014 VMware, Inc.
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

from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_vmware import vim_util

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.dvs import dvs_utils

LOG = logging.getLogger(__name__)


class DvsManager(object):
    """Management class for dvs related tasks."""

    def __init__(self):
        """Initializer.

        A global session with the VC will be established. In addition to this
        the moref of the configured DVS will be learnt. This will be used in
        the operations supported by the manager.

        NOTE: the DVS port group name will be the Neutron network UUID.
        """
        self._session = dvs_utils.dvs_create_session()
        # In the future we may decide to support more than one DVS
        self._dvs_moref = self._get_dvs_moref(self._session,
                                              dvs_utils.dvs_name_get())

    def _get_dvs_moref(self, session, dvs_name):
        """Get the moref of the configured DVS."""
        results = session.invoke_api(vim_util,
                                     'get_objects',
                                     session.vim,
                                     'DistributedVirtualSwitch',
                                     100)
        while results:
            for dvs in results.objects:
                for prop in dvs.propSet:
                    if dvs_name == prop.val:
                        vim_util.cancel_retrieval(session.vim, results)
                        return dvs.obj
            results = vim_util.continue_retrieval(session.vim, results)
        raise nsx_exc.DvsNotFound(dvs=dvs_name)

    def _get_port_group_spec(self, net_id, vlan_tag):
        """Gets the port groups spec for net_id and vlan_tag."""
        client_factory = self._session.vim.client.factory
        pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.name = net_id
        pg_spec.type = 'ephemeral'
        config = client_factory.create('ns0:VMwareDVSPortSetting')
        if vlan_tag:
            # Create the spec for the vlan tag
            spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
            vl_spec = client_factory.create(spec_ns)
            vl_spec.vlanId = vlan_tag
            vl_spec.inherited = '0'
            config.vlan = vl_spec
        pg_spec.defaultPortConfig = config
        return pg_spec

    def add_port_group(self, net_id, vlan_tag=None):
        """Add a new port group to the configured DVS."""
        pg_spec = self._get_port_group_spec(net_id, vlan_tag)
        task = self._session.invoke_api(self._session.vim,
                                        'CreateDVPortgroup_Task',
                                        self._dvs_moref,
                                        spec=pg_spec)
        try:
            # NOTE(garyk): cache the returned moref
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to create port group for '
                                  '%(net_id)s with tag %(tag)s.'),
                              {'net_id': net_id, 'tag': vlan_tag})
        LOG.info(_LI("%(net_id)s with tag %(vlan_tag)s created on %(dvs)s."),
                 {'net_id': net_id,
                  'vlan_tag': vlan_tag,
                  'dvs': dvs_utils.dvs_name_get()})

    def _net_id_to_moref(self, net_id):
        """Gets the moref for the specific neutron network."""
        # NOTE(garyk): return this from a cache if not found then invoke
        # code below.
        port_groups = self._session.invoke_api(vim_util,
                                               'get_object_properties',
                                               self._session.vim,
                                               self._dvs_moref,
                                               ['portgroup'])
        if len(port_groups) and hasattr(port_groups[0], 'propSet'):
            for prop in port_groups[0].propSet:
                for val in prop.val[0]:
                    props = self._session.invoke_api(vim_util,
                                                     'get_object_properties',
                                                     self._session.vim,
                                                     val, ['name'])
                    if len(props) and hasattr(props[0], 'propSet'):
                        for prop in props[0].propSet:
                            if net_id == prop.val:
                                # NOTE(garyk): update cache
                                return val
        raise exceptions.NetworkNotFound(net_id=net_id)

    def delete_port_group(self, net_id):
        """Delete a specific port group."""
        moref = self._net_id_to_moref(net_id)
        task = self._session.invoke_api(self._session.vim,
                                        'Destroy_Task',
                                        moref)
        try:
            self._session.wait_for_task(task)
        except Exception:
            # NOTE(garyk): handle more specific exceptions
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete port group for %s.'),
                              net_id)
        LOG.info(_LI("%(net_id)s delete from %(dvs)s."),
                 {'net_id': net_id,
                  'dvs': dvs_utils.dvs_name_get()})
