# Copyright 2016 VMware, Inc.  All rights reserved.
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

from vmware_nsx._i18n import _LI
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import trust_management

from neutron.callbacks import registry
from neutron import context
from oslo_config import cfg

LOG = logging.getLogger(__name__)

# default certificate validity period in days (10 years)
DEFAULT_CERT_VALIDITY_PERIOD = 3650


def get_certificate_manager(**kwargs):
    username, password = None, None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        username = properties.get('user')
        password = properties.get('password')

    storage_driver_type = cfg.CONF.nsx_v3.nsx_client_cert_storage.lower()
    LOG.info(_LI("Certificate storage is %s"), storage_driver_type)
    if storage_driver_type == 'nsx-db':
        storage_driver = cert_utils.DbCertificateStorageDriver(
            context.get_admin_context())
    elif storage_driver_type == 'none':
        storage_driver = cert_utils.DummyCertificateStorageDriver()
    # TODO(annak) - add support for barbican storage driver

    nsx_client = utils.get_nsxv3_client(username, password, True)
    nsx_trust = trust_management.NsxLibTrustManagement(nsx_client, {})

    return client_cert.ClientCertificateManager(
            cert_utils.NSX_OPENSTACK_IDENTITY,
            nsx_trust,
            storage_driver)


@admin_utils.output_header
def generate_cert(resource, event, trigger, **kwargs):
    """Generate self signed client certificate and private key
    """

    cert_manager = get_certificate_manager(**kwargs)
    if cert_manager.exists():
        # Need to delete cert first
        cert_manager.delete()

    cert_manager.generate(subject={},
                          valid_for_days=DEFAULT_CERT_VALIDITY_PERIOD)


@admin_utils.output_header
def delete_cert(resource, event, trigger, **kwargs):
    """Delete client certificate and private key """

    cert_manager = get_certificate_manager(**kwargs)
    if cert_manager.exists():
        cert_manager.delete()


@admin_utils.output_header
def show_cert(resource, event, trigger, **kwargs):
    """Show client certificate details """

    cert_manager = get_certificate_manager(**kwargs)
    if cert_manager.exists():
        cert_pem, key_pem = cert_manager.get_pem()
        expires_on = cert_manager.expires_on()
        expires_in_days = cert_manager.expires_in_days()
        if expires_in_days > 0:
            LOG.info(_LI("Client certificate is valid. "
                         "Expires on %(date)s (in %(days)d days)"),
                     {'date': expires_on, 'days': expires_in_days})

        else:
            LOG.info(_LI("Client certificate expired on %s."), expires_on)

        LOG.info(cert_pem)
        # TODO(annak): show certificate details such as subject and crypto
        # and add verification same certificate is registered in NSX.
        # For imported certificate, fetch from NSX
    else:
        LOG.info(_LI("Client certificate was not registered in the system"))


registry.subscribe(generate_cert,
                   constants.CERTIFICATE,
                   shell.Operations.GENERATE.value)

registry.subscribe(show_cert,
                   constants.CERTIFICATE,
                   shell.Operations.SHOW.value)

registry.subscribe(delete_cert,
                   constants.CERTIFICATE,
                   shell.Operations.CLEAN.value)
