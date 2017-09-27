# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

import mock
from oslo_config import cfg

from neutron.tests.unit import testlib_api

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsx.plugins.nsx_v3 import utils


class NsxV3ClientCertProviderTestCase(testlib_api.SqlTestCase):

    CERT = "-----BEGIN CERTIFICATE-----\n" \
        "MIIDJTCCAg0CBFh36j0wDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMxEzAR\n" \
        "BgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAoMBU15T3JnMQ8wDQYDVQQLDAZNeVVu\n" \
        "aXQxEjAQBgNVBAMMCW15b3JnLmNvbTAeFw0xNzAxMTIyMDQyMzdaFw0yNzAxMTAy\n" \
        "MDQyMzdaMFcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMQ4wDAYD\n" \
        "VQQKDAVNeU9yZzEPMA0GA1UECwwGTXlVbml0MRIwEAYDVQQDDAlteW9yZy5jb20w\n" \
        "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/wsYintlWVaSeXwaSrdPa\n" \
        "+AHtL1ooH7q0uf6tt+6Rwiy10YRjAVJhapj9995gqgJ2402J+3gzNXLCbXjjDR/D\n" \
        "9xjAzKHu61r0AVNd9/0+8yXQrEDuzlwHSCKz+zjq5ZEZ7RkLIUdreaZJFPTCwry3\n" \
        "wuTnBfqcE7xWl6WfWR8evooV+ZzIfjQdoSliIyn3YGxNN5pc1P40qt0pxOsNBGXG\n" \
        "2FIZXpML8TpKw0ga/wE70CJd6tRvSsAADxQXehfKvGtHvlJYS+3cTahC7reQXJnc\n" \
        "qsjgYkiWyhhR4jdcTD/tDlVcJroM1jFVxpsCg/AU3srWWWeAGyVe42ZhqWVf0Urz\n" \
        "AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA/lLfmXe8wPyBhN/VMb5bu5Ey56qz+j\n" \
        "jCn7tz7FjRvsB9P0fLUDOBKNwyon3yopDNYJ4hnm4yKoHCHURQLZKWHzm0XKzE+4\n" \
        "cA/M13M8OEg5otnVVHhz1FPQWnJq7bLHh/KXYcc5Rkc7UeHEPj0sDjfUjCPGdepc\n" \
        "Ghu1ZcgHsL4JCuvcadG+RFGeDTug3yO92Fj2uFy5DlzzWOZSi4otpZRd9JZkAtZ1\n" \
        "umZRBJ2A504nJx4MplmNqvLNkmxMLKQdvZYNNiYr6icOavDOJA5RhzgoppJZkV2w\n" \
        "v2oC+8BFarXnZSk37HAWjwcaqzBLbIyPYpClW5IYMr8LiixSBACc+4w=\n" \
        "-----END CERTIFICATE-----\n"

    PKEY = "-----BEGIN PRIVATE KEY-----\n" \
        "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC/wsYintlWVaSe\n" \
        "XwaSrdPa+AHtL1ooH7q0uf6tt+6Rwiy10YRjAVJhapj9995gqgJ2402J+3gzNXLC\n" \
        "bXjjDR/D9xjAzKHu61r0AVNd9/0+8yXQrEDuzlwHSCKz+zjq5ZEZ7RkLIUdreaZJ\n" \
        "FPTCwry3wuTnBfqcE7xWl6WfWR8evooV+ZzIfjQdoSliIyn3YGxNN5pc1P40qt0p\n" \
        "xOsNBGXG2FIZXpML8TpKw0ga/wE70CJd6tRvSsAADxQXehfKvGtHvlJYS+3cTahC\n" \
        "7reQXJncqsjgYkiWyhhR4jdcTD/tDlVcJroM1jFVxpsCg/AU3srWWWeAGyVe42Zh\n" \
        "qWVf0UrzAgMBAAECggEBAJrGuie9cQy3KZzOdD614RaPMPbhTnKuUYOH0GEk4YFy\n" \
        "aaYDS0iiC30njf8HLs10y3JsOuyRNU6X6F24AGe68xW3/pm3UUjHXG0wGLry68wA\n" \
        "c1g/gFV/6FXUSnZc4m7uBjUX4yvRm5TK5oV8TaZZifsEar9xWvrZDx4RXpQEWhL0\n" \
        "L/TyrOZSfRtBgdWX6Ag4XQVsCfZxJoCi2ZyvaMBsWTH06x9AGo1Io5t1AmA9Hsfb\n" \
        "6BsSz186nqb0fq4UMfrWrSCz7M/1s03+hBOVICH2TdaRDZLtDVa1b2x4sFpfdp9t\n" \
        "VVxuSHxcmvzOPMIv3NXwj0VitTYYJDBFKoEfx1mzhNkCgYEA59gYyBfpsuCOevP2\n" \
        "tn7IeysbtaoKDzHE+ksjs3sAn6Vr2Y0Lbed26NpdIVL6u3HAteJxqrIh0zpkpAtp\n" \
        "akdqlj86oRaBUqLXxK3QNpUx19f7KN7UsVAbzUJSOm2n1piPg261ktfhtms2rxnQ\n" \
        "+9yluINu+z1wS4FG9SwrRmwwfsUCgYEA072Ma1sj2MER5tmQw1zLANkzP1PAkUdy\n" \
        "+oDuJmU9A3/+YSIkm8dGprFglPkLUaf1B15oN6wCJVMpB1lza3PM/YT70rpqc7cq\n" \
        "PHJXQlZFMBhyVfIkCv3wICTLD5phhgAWlzlwm094f2uAnbG6WUkrVfZajuh0pW53\n" \
        "1i0OTfxAvlcCgYEAkDB2oSM2JhjApDlMbA2HtAqIbkA1h2OlpSDMMFjEd4WTALdW\n" \
        "r2CwNHtyRkJsS92gQ750gPvOS6daZifuxLlr0cu7M+piPbmnRdvvzbKWUC40NyP2\n" \
        "1dwDnnGr4EjIhI9XWh+lb5EyAJjHZrlAnxOIQawEft6kE2FwdxSkSWUJ+B0CgYEA\n" \
        "n2xYDXzRwKGdmPK2zGFRd5IRw9yLYNcq+vGYXdBb4Aa+wOO0LJYd2+Qxk/jvTMvo\n" \
        "8WNjlIcuFmxGuAHhpUXLUhaOhFtXS0jdxCVTDd9muI+vhoaKHLyVz53kRhs20m2+\n" \
        "lJ3q6wUq9MU8UX8/j3pH5rFV/cOIEAbcs6W4337OQIECgYEAoLtQyqXjH45FlCQx\n" \
        "xK8dY+GuxIP+TIwiq23yhu3e+3LIgXJw8DwBFN5yJyH2HMnhGkD4PurEx2sGHeLO\n" \
        "EG6L8PNDOxpvSzcgxwmZsUK6j3nAbKycF3PDDXA4kt8WDXBr86OMQsFtpjeO+fGh\n" \
        "YWJa+OKc2ExdeMewe9gKIDQ5stw=\n" \
        "-----END PRIVATE KEY-----\n"

    def _init_config(self, storage_type='nsx-db',
                     password=None, cert_file=None):
        cfg.CONF.set_override('nsx_use_client_auth', True, 'nsx_v3')
        cfg.CONF.set_override('nsx_client_cert_storage',
                              storage_type, 'nsx_v3')

        cfg.CONF.set_override('nsx_client_cert_file', cert_file, 'nsx_v3')
        cfg.CONF.set_override('nsx_client_cert_pk_password',
                              password, 'nsx_v3')

        # pk password secret is cached - reset it for each test
        cert_utils.reset_secret()

        self._provider = utils.get_client_cert_provider()

    def validate_db_provider(self, expected_cert_data):
        fname = None
        with self._provider() as p:
            # verify cert data was exported to CERTFILE
            fname = p.filename()
            with open(fname, 'r') as f:
                actual = f.read()

            self.assertEqual(expected_cert_data, actual)

        # after with statement, cert file should be deleted
        self.assertFalse(os.path.isfile(fname))

    def validate_basic_provider(self, expected_cert_data):
        fname = None
        with self._provider as p:
            fname = p.filename()
            with open(fname, 'r') as f:
                actual = f.read()

            self.assertEqual(expected_cert_data, actual)

        # with statement should not touch the file
        self.assertTrue(os.path.isfile(fname))

    def test_db_provider_without_cert(self):
        """Verify init fails if no cert is provided in client cert mode"""
        # certificate not generated - exception should be raised
        self._init_config()

        # no certificate in table
        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(None, None)).start()
        self.assertRaises(nsx_exc.ClientCertificateException,
                          self._provider().__enter__)

        # now verify return to normal after failure
        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, self.PKEY)).start()

        self.validate_db_provider(self.CERT + self.PKEY)

    def test_db_provider_with_cert(self):
        """Verify successful certificate load from storage"""

        self._init_config()

        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, self.PKEY)).start()

        self.validate_db_provider(self.CERT + self.PKEY)

    def test_db_provider_with_encryption(self):
        """Verify successful encrypted PK load from storage"""

        password = 'topsecret'
        self._init_config(password=password)
        secret = cert_utils.generate_secret_from_password(password)
        encrypted_pkey = cert_utils.symmetric_encrypt(secret, self.PKEY)

        # db should contain encrypted key
        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, encrypted_pkey)).start()

        self.validate_db_provider(self.CERT + self.PKEY)

    def test_db_provider_with_bad_decrypt(self):
        """Verify loading plaintext PK from storage fails in encrypt mode"""

        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, self.PKEY)).start()
        # after decrypt failure, cert will be deleted
        mock.patch(
            "vmware_nsx.db.db.delete_certificate").start()

        self._init_config(password='topsecret')

        # since PK in DB is not encrypted, we should fail to decrypt it on load
        self.assertRaises(nsx_exc.ClientCertificateException,
                          self._provider().__enter__)

    def test_basic_provider(self):

        fname = '/tmp/cert.pem'
        # with basic provider, the file is provided by admin
        with open(fname, 'w') as f:
            f.write(self.CERT)
            f.write(self.PKEY)

        self._init_config(storage_type='none', cert_file=fname)
        with self._provider as p:
            self.assertEqual(fname, p.filename())

        self.validate_basic_provider(self.CERT + self.PKEY)
        os.remove(fname)
