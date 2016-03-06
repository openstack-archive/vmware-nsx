# Copyright 2016 VMware, Inc.
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
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes as attr
from neutron.db import db_base_plugin_v2
from neutron.extensions import securitygroup as ext_sg
from neutron_lib import exceptions as nexception
from vmware_nsx._i18n import _
from vmware_nsx.db import nsxv_models
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as ext_loip


class NotIngressRule(nexception.BadRequest):
    message = _("Specifying local_ip_prefix is supported "
                "with ingress rules only.")


class ExtendedSecurityGroupRuleMixin(object):

    def _check_local_ip_prefix(self, context, rule):
        rule_specify_local_ip_prefix = attr.is_attr_set(
            rule.get(ext_loip.LOCAL_IP_PREFIX))
        if rule_specify_local_ip_prefix and rule['direction'] != 'ingress':
            raise NotIngressRule()
        return rule_specify_local_ip_prefix

    def _save_extended_rule_properties(self, context, rule):
        if not attr.is_attr_set(rule.get(ext_loip.LOCAL_IP_PREFIX)):
            return
        with context.session.begin(subtransactions=True):
            properties = nsxv_models.NsxvExtendedSecurityGroupRuleProperties(
                rule_id=rule['id'],
                local_ip_prefix=rule[ext_loip.LOCAL_IP_PREFIX])
            context.session.add(properties)

    def _get_security_group_rule_properties(self, context, sgr):
        try:
            properties = (context.session.query(
                nsxv_models.NsxvExtendedSecurityGroupRuleProperties).filter_by(
                    rule_id=sgr['id']).one())
        except exc.NoResultFound:
            sgr[ext_loip.LOCAL_IP_PREFIX] = None
        else:
            sgr[ext_loip.LOCAL_IP_PREFIX] = properties.local_ip_prefix
        return sgr

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        ext_sg.SECURITYGROUPRULES, ['_extend_security_group_rule_with_params'])

    def _extend_security_group_rule_with_params(self, sg_rule_res, sg_rule_db):
        if sg_rule_db.ext_properties:
            sg_rule_res[ext_loip.LOCAL_IP_PREFIX] = (
                sg_rule_db.ext_properties.local_ip_prefix)
        else:
            sg_rule_res[ext_loip.LOCAL_IP_PREFIX] = None
