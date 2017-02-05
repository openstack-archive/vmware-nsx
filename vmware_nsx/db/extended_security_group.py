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

from neutron_lib.db import model_base
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import utils as n_utils
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db.models import securitygroup as securitygroups_db  # noqa
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api import validators
from neutron_lib import constants as n_constants

from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging


class NsxExtendedSecurityGroupProperties(model_base.BASEV2):
    __tablename__ = 'nsx_extended_security_group_properties'

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('securitygroups.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    logging = sa.Column(sa.Boolean, default=False, nullable=False)
    provider = sa.Column(sa.Boolean, default=False, nullable=False)
    security_group = orm.relationship(
        securitygroups_db.SecurityGroup,
        backref=orm.backref('ext_properties', lazy='joined',
                            uselist=False, cascade='delete'))


class ExtendedSecurityGroupPropertiesMixin(object):

    # NOTE(arosen): here we add a relationship so that from the ports model
    # it provides us access to SecurityGroupPortBinding and
    # NsxExtendedSecurityGroupProperties
    securitygroups_db.SecurityGroupPortBinding.extended_grp = orm.relationship(
        'NsxExtendedSecurityGroupProperties',
        foreign_keys="SecurityGroupPortBinding.security_group_id",
        primaryjoin=("NsxExtendedSecurityGroupProperties.security_group_id"
                     "==SecurityGroupPortBinding.security_group_id"))

    def create_provider_security_group(self, context, security_group):
        """Create a provider security group.

        This method creates a security group that does not by default
        enable egress traffic which normal neutron security groups do.
        """
        s = security_group['security_group']
        tenant_id = s['tenant_id']

        with db_api.autonested_transaction(context.session):
            security_group_db = securitygroups_db.SecurityGroup(
                id=s.get('id') or (uuidutils.generate_uuid()),
                description=s.get('description', ''),
                tenant_id=tenant_id,
                name=s.get('name', ''))
            context.session.add(security_group_db)
        secgroup_dict = self._make_security_group_dict(security_group_db)
        secgroup_dict[provider_sg.PROVIDER] = True
        return secgroup_dict

    def _process_security_group_properties_create(self, context,
                                                  sg_res, sg_req,
                                                  default_sg=False):
        self._validate_security_group_properties_create(
            context, sg_req, default_sg)
        with context.session.begin(subtransactions=True):
            properties = NsxExtendedSecurityGroupProperties(
                security_group_id=sg_res['id'],
                logging=sg_req.get(sg_logging.LOGGING, False),
                provider=sg_req.get(provider_sg.PROVIDER, False))
            context.session.add(properties)
        sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)
        sg_res[provider_sg.PROVIDER] = sg_req.get(provider_sg.PROVIDER, False)

    def _get_security_group_properties(self, context, security_group_id):
        with context.session.begin(subtransactions=True):
            try:
                prop = context.session.query(
                    NsxExtendedSecurityGroupProperties).filter_by(
                        security_group_id=security_group_id).one()
            except exc.NoResultFound:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)
        return prop

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

    def _is_provider_security_group(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return sg_prop.provider

    def _check_provider_security_group_exists(self, context,
                                              security_group_id):
        # NOTE(roeyc): We want to retrieve the security-group info by calling
        # get_security_group, this will also validate that the provider
        # security-group belongs to the same tenant this request is made for.
        sg = self.get_security_group(context, security_group_id)
        if not sg[provider_sg.PROVIDER]:
            raise provider_sg.SecurityGroupNotProvider(id=sg)

    def _check_invalid_security_groups_specified(self, context, port):
        if validators.is_attr_set(port.get(ext_sg.SECURITYGROUPS)):
            for sg in port.get(ext_sg.SECURITYGROUPS, []):
                # makes sure user doesn't add non-provider secgrp as secgrp
                if self._is_provider_security_group(context, sg):
                    raise provider_sg.SecurityGroupIsProvider(id=sg)

        if validators.is_attr_set(
                port.get(provider_sg.PROVIDER_SECURITYGROUPS)):

            # also check all provider groups are provider.
            for sg in port.get(provider_sg.PROVIDER_SECURITYGROUPS, []):
                self._check_provider_security_group_exists(context, sg)

    def _get_tenant_provider_security_groups(self, context, tenant_id):
        res = context.session.query(
            NsxExtendedSecurityGroupProperties.security_group_id
        ).join(securitygroups_db.SecurityGroup).filter(
            securitygroups_db.SecurityGroup.tenant_id == tenant_id,
            NsxExtendedSecurityGroupProperties.provider == sa.true()).scalar()
        return [res] if res else []

    def _validate_security_group_properties_create(self, context,
                                                   security_group, default_sg):
        self._validate_provider_security_group_create(context, security_group,
                                                      default_sg)

    def _validate_provider_security_group_create(self, context, security_group,
                                                 default_sg):
        if not security_group.get(provider_sg.PROVIDER, False):
            return

        if default_sg:
            raise provider_sg.DefaultSecurityGroupIsNotProvider()

        tenant_id = security_group['tenant_id']
        ssg = self._get_tenant_provider_security_groups(context, tenant_id)
        if ssg:
            raise provider_sg.TenantProviderSecurityExists(id=ssg,
                                                           tenant_id=tenant_id)

    def _get_provider_security_groups_on_port(self, context, port):
        p = port['port']
        tenant_id = p['tenant_id']
        provider_sgs = p.get(provider_sg.PROVIDER_SECURITYGROUPS,
                             n_constants.ATTR_NOT_SPECIFIED)

        if p.get('device_owner') and n_utils.is_port_trusted(p):
            return

        self._check_invalid_security_groups_specified(context, p)

        if not validators.is_attr_set(provider_sgs):
            if provider_sgs is n_constants.ATTR_NOT_SPECIFIED:
                provider_sgs = self._get_tenant_provider_security_groups(
                    context, tenant_id)
            else:
                # Accept None as indication that this port should not be
                # associated with any provider security-group.
                provider_sgs = []
        return provider_sgs

    def _process_port_create_provider_security_group(self, context, p,
                                                     security_group_ids):
        if validators.is_attr_set(security_group_ids):
            for security_group_id in security_group_ids:
                self._create_port_security_group_binding(context, p['id'],
                                                         security_group_id)
        p[provider_sg.PROVIDER_SECURITYGROUPS] = security_group_ids or []

    def _process_port_update_provider_security_group(self, context, port,
                                                     original_port,
                                                     updated_port):
        p = port['port']
        provider_sg_specified = (provider_sg.PROVIDER_SECURITYGROUPS in p and
                                 p[provider_sg.PROVIDER_SECURITYGROUPS] !=
                                 n_constants.ATTR_NOT_SPECIFIED)
        provider_sg_changed = (
            provider_sg_specified and not n_utils.compare_elements(
                original_port[provider_sg.PROVIDER_SECURITYGROUPS],
                p[provider_sg.PROVIDER_SECURITYGROUPS]))
        sg_changed = (
            set(original_port[ext_sg.SECURITYGROUPS]) !=
            set(updated_port[ext_sg.SECURITYGROUPS]))

        if provider_sg_changed:
            port['port']['tenant_id'] = original_port['id']
            port['port']['id'] = original_port['id']
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                self._get_provider_security_groups_on_port(context, port))
        else:
            if sg_changed:
                self._check_invalid_security_groups_specified(context, p)
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                original_port[provider_sg.PROVIDER_SECURITYGROUPS])

        if provider_sg_changed or sg_changed:
            if not sg_changed:
                query = context.session.query(
                    securitygroups_db.SecurityGroupPortBinding)
                for sg in original_port[provider_sg.PROVIDER_SECURITYGROUPS]:
                    binding = query.filter_by(
                        port_id=p['id'], security_group_id=sg).one()
                    context.session.delete(binding)
            self._process_port_create_provider_security_group(
                context, updated_port,
                updated_port[provider_sg.PROVIDER_SECURITYGROUPS])
        return provider_sg_changed

    def _prevent_non_admin_delete_provider_sg(self, context, sg_id):
        # Only someone who is an admin is allowed to delete this.
        if not context.is_admin and self._is_provider_security_group(context,
                                                                     sg_id):
            raise provider_sg.ProviderSecurityGroupDeleteNotAdmin(id=sg_id)

    def _extend_security_group_with_properties(self, sg_res, sg_db):
        if sg_db.ext_properties:
            sg_res[sg_logging.LOGGING] = sg_db.ext_properties.logging
            sg_res[provider_sg.PROVIDER] = sg_db.ext_properties.provider

    def _extend_port_dict_provider_security_group(self, port_res, port_db):
        # NOTE(arosen): this method overrides the one in the base
        # security group db class. The reason this is needed is because
        # we are storing provider security groups in the same security
        # groups db model. We need to do this here to remove the provider
        # security groups and put those on the port resource as their
        # own attribute.

        # Security group bindings will be retrieved from the SQLAlchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.

        provider_groups = []
        not_provider_groups = []
        for sec_group_mapping in port_db.security_groups:
            if sec_group_mapping.extended_grp.provider is True:
                provider_groups.append(sec_group_mapping['security_group_id'])
            else:
                not_provider_groups.append(
                    sec_group_mapping['security_group_id'])

        port_res[ext_sg.SECURITYGROUPS] = not_provider_groups
        port_res[provider_sg.PROVIDER_SECURITYGROUPS] = provider_groups
        return port_res

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_extend_port_dict_provider_security_group'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        ext_sg.SECURITYGROUPS, ['_extend_security_group_with_properties'])
