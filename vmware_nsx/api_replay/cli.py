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

import argparse

from vmware_nsx.api_replay import client


class ApiReplayCli(object):

    def __init__(self):
        args = self._setup_argparse()
        client.ApiReplayClient(
            source_os_tenant_name=args.source_os_tenant_name,
            source_os_username=args.source_os_username,
            source_os_password=args.source_os_password,
            source_os_auth_url=args.source_os_auth_url,
            dest_os_username=args.dest_os_username,
            dest_os_tenant_name=args.dest_os_tenant_name,
            dest_os_password=args.dest_os_password,
            dest_os_auth_url=args.dest_os_auth_url)

    def _setup_argparse(self):
        parser = argparse.ArgumentParser()

        # Arguements required to connect to source
        # neutron which we will fetch all of the data from.
        parser.add_argument(
            "--source-os-username",
            required=True,
            help="The source os-username to use to "
                 "gather neutron resources with.")
        parser.add_argument(
            "--source-os-tenant-name",
            required=True,
            help="The source os-tenant-name to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--source-os-password",
            required=True,
            help="The password for this user.")
        parser.add_argument(
            "--source-os-auth-url",
            required=True,
            help="They keystone api endpoint for this user.")

        # Arguements required to connect to the dest neutron which
        # we will recreate all of these resources over.
        parser.add_argument(
            "--dest-os-username",
            required=True,
            help="The dest os-username to use to"
                 "gather neutron resources with.")
        parser.add_argument(
            "--dest-os-tenant-name",
            required=True,
            help="The dest os-tenant-name to use to "
                 "gather neutron resource with.")
        parser.add_argument(
            "--dest-os-password",
            required=True,
            help="The password for this user.")
        parser.add_argument(
            "--dest-os-auth-url",
            required=True,
            help="They keystone api endpoint for this user.")

        # NOTE: this will return an error message if any of the
        # require options are missing.
        return parser.parse_args()


def main():
    ApiReplayCli()
