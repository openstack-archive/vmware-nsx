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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg

from vmware_nsx.extensions import securitygrouplogging as sg_logging


class NsxExtendedSecurityGroupProperties(model_base.BASEV2):
    __tablename__ = 'nsx_extended_security_group_properties'

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('securitygroups.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    logging = sa.Column(sa.Boolean, default=False, nullable=False)
    security_group = orm.relationship(
        securitygroups_db.SecurityGroup,
        backref=orm.backref('ext_properties', lazy='joined',
                            uselist=False, cascade='delete'))


class ExtendedSecurityGroupPropertiesMixin(object):

    def _process_security_group_properties_create(self, context,
                                                  sg_res, sg_req):
        with context.session.begin(subtransactions=True):
            properties = NsxExtendedSecurityGroupProperties(
                security_group_id=sg_res['id'],
                logging=sg_req.get(sg_logging.LOGGING, False))
            context.session.add(properties)
        sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)

    def _get_security_group_properties(self, context, security_group_id):
        return context.session.query(
            NsxExtendedSecurityGroupProperties).filter_by(
                security_group_id=security_group_id).one()

    def _process_security_group_properties_update(self, context,
                                                  sg_res, sg_req):
        if (sg_logging.LOGGING in sg_req
                and (sg_req[sg_logging.LOGGING] !=
                     sg_res.get(sg_logging.LOGGING, False))):
            prop = self._get_security_group_properties(context, sg_res['id'])
            with context.session.begin(subtransactions=True):
                prop.update({sg_logging.LOGGING: sg_req[sg_logging.LOGGING]})
            sg_res[sg_logging.LOGGING] = sg_req[sg_logging.LOGGING]

    def _is_security_group_logged(self, context, security_group_id):
        prop = self._get_security_group_properties(context, security_group_id)
        return prop.logging

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        ext_sg.SECURITYGROUPS, ['_extend_security_group_with_properties'])

    def _extend_security_group_with_properties(self, sg_res, sg_db):
        if sg_db.ext_properties:
            sg_res[sg_logging.LOGGING] = sg_db.ext_properties.logging
