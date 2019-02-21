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

from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron.db.models import securitygroup as securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_constants
from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.db import resource_extend
from neutron_lib.objects import registry as obj_reg
from neutron_lib.utils import helpers
from neutron_lib.utils import net as n_utils

from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.extensions import securitygrouppolicy as sg_policy


LOG = logging.getLogger(__name__)


class NsxExtendedSecurityGroupProperties(model_base.BASEV2):
    __tablename__ = 'nsx_extended_security_group_properties'

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('securitygroups.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    logging = sa.Column(sa.Boolean, default=False, nullable=False)
    provider = sa.Column(sa.Boolean, default=False, server_default=sql.false(),
                         nullable=False)
    policy = sa.Column(sa.String(36))
    security_group = orm.relationship(
        securitygroups_db.SecurityGroup,
        backref=orm.backref('ext_properties', lazy='joined',
                            uselist=False, cascade='delete'))


@resource_extend.has_resource_extenders
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
        return self.create_security_group_without_rules(
            context, security_group, False, True)

    def create_security_group_without_rules(self, context, security_group,
                                            default_sg, is_provider):
        """Create a neutron security group, without any default rules.

        This method creates a security group that does not by default
        enable egress traffic which normal neutron security groups do.
        """
        s = security_group['security_group']
        kwargs = {
            'context': context,
            'security_group': s,
            'is_default': default_sg,
        }

        self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_CREATE,
                              exc_cls=ext_sg.SecurityGroupConflict,
                              payload=events.DBEventPayload(
                                  context, metadata={'is_default': default_sg},
                                  request_body=security_group,
                                  desired_state=s))

        tenant_id = s['tenant_id']

        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        with db_api.CONTEXT_WRITER.using(context):
            sg = obj_reg.new_instance(
                'SecurityGroup', context,
                id=s.get('id') or uuidutils.generate_uuid(),
                description=s.get('description', ''), project_id=tenant_id,
                name=s.get('name', ''), is_default=default_sg)
            # Note(asarfaty): for unknown reason, removing the 'is_default'
            # here allows the loading of the ext_properties of the security
            # group. If not - we will get DetachedInstanceError
            if 'is_default' in sg.fields_no_update:
                sg.fields_no_update.remove('is_default')
            sg.create()

        secgroup_dict = self._make_security_group_dict(sg)
        secgroup_dict[sg_policy.POLICY] = s.get(sg_policy.POLICY)
        secgroup_dict[provider_sg.PROVIDER] = is_provider
        kwargs['security_group'] = secgroup_dict
        registry.notify(resources.SECURITY_GROUP, events.AFTER_CREATE, self,
                        **kwargs)
        return secgroup_dict

    def _process_security_group_properties_create(self, context,
                                                  sg_res, sg_req,
                                                  default_sg=False):
        self._validate_security_group_properties_create(
            context, sg_req, default_sg)
        with db_api.CONTEXT_WRITER.using(context):
            properties = NsxExtendedSecurityGroupProperties(
                security_group_id=sg_res['id'],
                logging=sg_req.get(sg_logging.LOGGING, False),
                provider=sg_req.get(provider_sg.PROVIDER, False),
                policy=sg_req.get(sg_policy.POLICY))
            context.session.add(properties)
        sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)
        sg_res[provider_sg.PROVIDER] = sg_req.get(provider_sg.PROVIDER, False)
        sg_res[sg_policy.POLICY] = sg_req.get(sg_policy.POLICY)

    def _get_security_group_properties(self, context, security_group_id):
        with db_api.CONTEXT_READER.using(context):
            try:
                prop = context.session.query(
                    NsxExtendedSecurityGroupProperties).filter_by(
                        security_group_id=security_group_id).one()
            except exc.NoResultFound:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)
        return prop

    def _process_security_group_properties_update(self, context,
                                                  sg_res, sg_req):
        if ((sg_logging.LOGGING in sg_req and
             (sg_req[sg_logging.LOGGING] !=
              sg_res.get(sg_logging.LOGGING, False))) or
            (sg_policy.POLICY in sg_req and
             (sg_req[sg_policy.POLICY] !=
              sg_res.get(sg_policy.POLICY)))):
            with db_api.CONTEXT_WRITER.using(context):
                prop = context.session.query(
                    NsxExtendedSecurityGroupProperties).filter_by(
                        security_group_id=sg_res['id']).one()
                prop.logging = sg_req.get(sg_logging.LOGGING, False)
                prop.policy = sg_req.get(sg_policy.POLICY)

            sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)
            sg_res[sg_policy.POLICY] = sg_req.get(sg_policy.POLICY)

    def _is_security_group_logged(self, context, security_group_id):
        prop = self._get_security_group_properties(context, security_group_id)
        return prop.logging

    def _is_provider_security_group(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return sg_prop.provider

    def _is_policy_security_group(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return True if sg_prop.policy else False

    def _get_security_group_policy(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return sg_prop.policy

    def _check_provider_security_group_exists(self, context,
                                              security_group_id):
        # NOTE(roeyc): We want to retrieve the security-group info by calling
        # get_security_group, this will also validate that the provider
        # security-group belongs to the same tenant this request is made for.
        sg = self.get_security_group(context, security_group_id)
        if not sg[provider_sg.PROVIDER]:
            raise provider_sg.SecurityGroupNotProvider(id=security_group_id)

    def _check_invalid_security_groups_specified(self, context, port,
                                                 only_warn=False):
        """Check if the lists of security groups are valid

        When only_warn is True we do not raise an exception here, because this
        may fail nova boot.
        Instead we will later remove provider security groups from the regular
        security groups list of the port.
        Since all the provider security groups of the tenant will be on this
        list anyway, the result will be the same.
        """
        if validators.is_attr_set(port.get(ext_sg.SECURITYGROUPS)):
            for sg in port.get(ext_sg.SECURITYGROUPS, []):
                # makes sure user doesn't add non-provider secgrp as secgrp
                if self._is_provider_security_group(context, sg):
                    if only_warn:
                        LOG.warning(
                            "Ignored provider security group %(sg)s in "
                            "security groups list for port %(id)s",
                            {'sg': sg, 'id': port['id']})
                    else:
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
            NsxExtendedSecurityGroupProperties.provider == sa.true()).all()
        return [r[0] for r in res]

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

    def _get_provider_security_groups_on_port(self, context, port):
        p = port['port']
        tenant_id = p['tenant_id']
        provider_sgs = p.get(provider_sg.PROVIDER_SECURITYGROUPS,
                             n_constants.ATTR_NOT_SPECIFIED)

        if p.get('device_owner') and n_utils.is_port_trusted(p):
            return

        if not validators.is_attr_set(provider_sgs):
            if provider_sgs is n_constants.ATTR_NOT_SPECIFIED:
                provider_sgs = self._get_tenant_provider_security_groups(
                    context, tenant_id)
            else:
                # Accept None as indication that this port should not be
                # associated with any provider security-group.
                provider_sgs = []
        return provider_sgs

    def _get_port_security_groups_lists(self, context, port):
        """Return 2 lists of this port security groups:

        1) Regular security groups for this port
        2) Provider security groups for this port
        """
        port_data = port['port']
        # First check that the configuration is valid
        self._check_invalid_security_groups_specified(
            context, port_data, only_warn=True)

        # get the 2 separate lists of security groups
        sgids = self._get_security_groups_on_port(
            context, port) or []
        psgids = self._get_provider_security_groups_on_port(
            context, port) or []
        had_sgs = len(sgids) > 0

        # remove provider security groups which were specified also in the
        # regular sg list
        sgids = list(set(sgids) - set(psgids))
        if not len(sgids) and had_sgs:
            # Add the default sg of the tenant if no other remained
            tenant_id = port_data.get('tenant_id')
            default_sg = self._ensure_default_security_group(
                context, tenant_id)
            sgids.append(default_sg)

        return (sgids, psgids)

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
            provider_sg_specified and not helpers.compare_elements(
                original_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []),
                p[provider_sg.PROVIDER_SECURITYGROUPS]))
        sg_changed = (
            set(original_port[ext_sg.SECURITYGROUPS]) !=
            set(updated_port[ext_sg.SECURITYGROUPS]))
        if sg_changed or provider_sg_changed:
            self._check_invalid_security_groups_specified(context, p)

        if provider_sg_changed:
            port['port']['tenant_id'] = original_port['id']
            port['port']['id'] = original_port['id']
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                self._get_provider_security_groups_on_port(context, port))
        else:
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                original_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []))

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

    def _prevent_non_admin_edit_provider_sg(self, context, sg_id):
        # Only someone who is an admin is allowed to modify a provider sg.
        if not context.is_admin and self._is_provider_security_group(context,
                                                                     sg_id):
            raise provider_sg.ProviderSecurityGroupEditNotAdmin(id=sg_id)

    def _prevent_non_admin_delete_policy_sg(self, context, sg_id):
        # Only someone who is an admin is allowed to delete this.
        if not context.is_admin and self._is_policy_security_group(context,
                                                                   sg_id):
            raise sg_policy.PolicySecurityGroupDeleteNotAdmin(id=sg_id)

    @staticmethod
    @resource_extend.extends([ext_sg.SECURITYGROUPS])
    def _extend_security_group_with_properties(sg_res, sg_db):
        if sg_db.ext_properties:
            sg_res[sg_logging.LOGGING] = sg_db.ext_properties.logging
            sg_res[provider_sg.PROVIDER] = sg_db.ext_properties.provider
            sg_res[sg_policy.POLICY] = sg_db.ext_properties.policy

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_provider_security_group(port_res, port_db):
        # Add the provider sg list to the port.
        # later we will remove those from the regular sg list
        provider_groups = []
        for sec_group_mapping in port_db.security_groups:
            if (sec_group_mapping.extended_grp and
                sec_group_mapping.extended_grp.provider is True):
                provider_groups.append(sec_group_mapping['security_group_id'])
        port_res[provider_sg.PROVIDER_SECURITYGROUPS] = provider_groups
        return port_res

    @staticmethod
    def _remove_provider_security_groups_from_list(port_res):
        # Remove provider security groups from the list of regular security
        # groups of the result port
        if (ext_sg.SECURITYGROUPS not in port_res or
            provider_sg.PROVIDER_SECURITYGROUPS not in port_res):
            return

        port_res[ext_sg.SECURITYGROUPS] = list(
            set(port_res[ext_sg.SECURITYGROUPS]) -
            set(port_res[provider_sg.PROVIDER_SECURITYGROUPS]))
