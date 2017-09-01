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
import os
import random

from oslo_config import cfg
from oslo_log import log as logging

from neutron import version as n_version
from neutron_lib import context as q_context

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import config

NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'

LOG = logging.getLogger(__name__)


class DbCertProvider(client_cert.ClientCertProvider):
    """Write cert data from DB to file and delete after use

       New provider object with random filename is created for each request.
       This is not most efficient, but the safest way to avoid race conditions,
       since backend connections can occur both before and after neutron
       fork, and several concurrent requests can occupy the same thread.
       Note that new cert filename for each request does not result in new
       connection for each request (at least for now..)
    """
    EXPIRATION_ALERT_DAYS = 30          # days prior to expiration

    def __init__(self):
        super(DbCertProvider, self).__init__(None)
        random.seed()
        self._filename = '/tmp/.' + str(random.randint(1, 10000000))

    def _check_expiration(self, expires_in_days):
        if expires_in_days > self.EXPIRATION_ALERT_DAYS:
            return

        if expires_in_days < 0:
            LOG.error("Client certificate has expired %d days ago.",
                      expires_in_days * -1)
        else:
            LOG.warning("Client certificate expires in %d days. "
                        "Once expired, service will become unavailable.",
                        expires_in_days)

    def __enter__(self):
            try:
                context = q_context.get_admin_context()
                db_storage_driver = cert_utils.DbCertificateStorageDriver(
                    context)
                with client_cert.ClientCertificateManager(
                    cert_utils.NSX_OPENSTACK_IDENTITY,
                    None,
                    db_storage_driver) as cert_manager:
                    if not cert_manager.exists():
                        msg = _("Unable to load from nsx-db")
                        raise nsx_exc.ClientCertificateException(err_msg=msg)

                    filename = self._filename
                    if not os.path.exists(os.path.dirname(filename)):
                        if len(os.path.dirname(filename)) > 0:
                            os.makedirs(os.path.dirname(filename))
                    cert_manager.export_pem(filename)

                    expires_in_days = cert_manager.expires_in_days()
                    self._check_expiration(expires_in_days)
            except Exception as e:
                self._on_exit()
                raise e

            return self

    def _on_exit(self):
        if os.path.isfile(self._filename):
            os.remove(self._filename)

        self._filename = None

    def __exit__(self, type, value, traceback):
        self._on_exit()

    def filename(self):
        return self._filename


def get_client_cert_provider():
    if not cfg.CONF.nsx_v3.nsx_use_client_auth:
        return None

    if cfg.CONF.nsx_v3.nsx_client_cert_storage.lower() == 'none':
        # Admin is responsible for providing cert file, the plugin
        # should not touch it
        return client_cert.ClientCertProvider(
                cfg.CONF.nsx_v3.nsx_client_cert_file)

    if cfg.CONF.nsx_v3.nsx_client_cert_storage.lower() == 'nsx-db':
        # Cert data is stored in DB, and written to file system only
        # when new connection is opened, and deleted immediately after.
        return DbCertProvider


def get_nsxlib_wrapper(nsx_username=None, nsx_password=None, basic_auth=False):
    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider()

    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or cfg.CONF.nsx_v3.nsx_api_user,
        password=nsx_password or cfg.CONF.nsx_v3.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=cfg.CONF.nsx_v3.http_retries,
        insecure=cfg.CONF.nsx_v3.insecure,
        ca_file=cfg.CONF.nsx_v3.ca_file,
        concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
        http_timeout=cfg.CONF.nsx_v3.http_timeout,
        http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
        conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
        http_provider=None,
        max_attempts=cfg.CONF.nsx_v3.retries,
        nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain)
    return v3.NsxLib(nsxlib_config)
