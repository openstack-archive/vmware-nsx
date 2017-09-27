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

import base64
import hashlib

from cryptography import fernet
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.db import db as nsx_db

LOG = logging.getLogger(__name__)
NSX_OPENSTACK_IDENTITY = "com.vmware.nsx.openstack"

# 32-byte base64-encoded secret for symmetric password encryption
# generated on init based on password provided in configuration
_SECRET = None


def reset_secret():
    global _SECRET
    _SECRET = None


def generate_secret_from_password(password):
    m = hashlib.md5()
    m.update(password.encode('ascii'))
    return base64.b64encode(m.hexdigest().encode('ascii'))


def symmetric_encrypt(secret, plaintext):
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('ascii')
    return fernet.Fernet(secret).encrypt(plaintext).decode('ascii')


def symmetric_decrypt(secret, ciphertext):
    if not isinstance(ciphertext, bytes):
        ciphertext = ciphertext.encode('ascii')
    return fernet.Fernet(secret).decrypt(ciphertext).decode('ascii')


class DbCertificateStorageDriver(object):
    """Storage for certificate and private key in neutron DB"""
    def __init__(self, context):
        global _SECRET
        self._context = context
        if cfg.CONF.nsx_v3.nsx_client_cert_pk_password and not _SECRET:
            _SECRET = generate_secret_from_password(
                    cfg.CONF.nsx_v3.nsx_client_cert_pk_password)

    def store_cert(self, purpose, certificate, private_key):
        # encrypt private key
        if _SECRET:
            private_key = symmetric_encrypt(_SECRET, private_key)

        nsx_db.save_certificate(self._context.session, purpose,
                                certificate, private_key)

    def get_cert(self, purpose):
        cert, private_key = nsx_db.get_certificate(self._context.session,
                                                   purpose)
        if _SECRET and private_key:
            try:
                # Encrypted PK is stored in DB as string, while fernet expects
                # bytearray.
                private_key = symmetric_decrypt(_SECRET, private_key)
            except fernet.InvalidToken:
                # unable to decrypt - probably due to change of password
                # cert and PK are useless, need to delete them
                LOG.error("Unable to decrypt private key, possibly due "
                          "to change of password. Certificate needs to be "
                          "regenerated")
                self.delete_cert(purpose)
                return None, None

        return cert, private_key

    def delete_cert(self, purpose):
        return nsx_db.delete_certificate(self._context.session, purpose)


class DummyCertificateStorageDriver(object):
    """Dummy driver API implementation

    Used for external certificate import scenario
    (nsx_client_cert_storage == None)
    """

    def store_cert(self, purpose, certificate, private_key):
        pass

    def get_cert(self, purpose):
        return None, None

    def delete_cert(self, purpose):
        pass
