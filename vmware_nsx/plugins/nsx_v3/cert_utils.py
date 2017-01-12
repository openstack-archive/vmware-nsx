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

from vmware_nsx.db import db as nsx_db


NSX_OPENSTACK_IDENTITY = "com.vmware.nsx.openstack"


class DbCertificateStorageDriver(object):
    """Storage for certificate and private key in neutron DB"""
    # TODO(annak): Add private key encryption
    def __init__(self, context):
        self._context = context

    def store_cert(self, purpose, certificate, private_key):
        nsx_db.save_certificate(self._context.session, purpose,
                                certificate, private_key)

    def get_cert(self, purpose):
        return nsx_db.get_certificate(self._context.session, purpose)

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
        pass

    def delete_cert(self, purpose):
        pass
