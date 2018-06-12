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

import logging
import xml.etree.ElementTree as et

from neutron_lbaas.db.loadbalancer import models as nlbaas_v2
from neutron_lib.callbacks import registry

from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield import vcns as nsxv_api
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common.utils import output_header
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as utils
from vmware_nsx.shell.resources import Operations

LBAAS_FW_SECTION_NAME = 'LBaaS FW Rules'
LOG = logging.getLogger(__name__)


@output_header
def sync_lbaas_dfw_rules(resource, event, trigger, **kwargs):
    vcns = utils.get_nsxv_client()
    with locking.LockManager.get_lock('lbaas-fw-section'):
        fw_section_id = vcns.get_section_id(LBAAS_FW_SECTION_NAME)
        if not fw_section_id:
            section = et.Element('section')
            section.attrib['name'] = LBAAS_FW_SECTION_NAME
            sect = vcns.create_section('ip', et.tostring(section))[1]
            fw_section_id = et.fromstring(sect).attrib['id']

        if not fw_section_id:
            LOG.error('No LBaaS FW Section id found')
            return

        neutron_db = utils.NeutronDbClient()
        pools = neutron_db.context.session.query(nlbaas_v2.PoolV2).all()
        pool_ids = [pool['id'] for pool in pools]

        section_uri = '%s/%s/%s' % (nsxv_api.FIREWALL_PREFIX,
                                    'layer3sections',
                                    fw_section_id)

        xml_section_data = vcns.get_section(section_uri)
        if xml_section_data:
            xml_section = xml_section_data[1]
        else:
            LOG.info('LBaaS XML section was not found!')
            return

        section = et.fromstring(xml_section)

        for rule in section.findall('.//rule'):
            if rule.find('name').text in pool_ids:
                LOG.info('Rule %s found and valid', rule.find('name').text)
            else:
                section.remove(rule)
                LOG.info('Rule %s is stale and removed',
                         rule.find('name').text)

        vcns.update_section(section_uri,
                            et.tostring(section, encoding="us-ascii"),
                            None)


registry.subscribe(sync_lbaas_dfw_rules,
                   constants.LBAAS,
                   Operations.NSX_UPDATE.value)
