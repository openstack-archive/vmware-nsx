# Copyright 2016 OpenStack Foundation
# All Rights Reserved.
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


from osc_lib import utils
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

DEFAULT_API_VERSION = '2'
API_VERSION_OPTION = 'vmware_nsx_api_version'
API_NAME = 'nsxclient'
API_VERSIONS = {
    '2.0': 'nsxclient.v2_0.client.Client',
    '2': 'nsxclient.v2_0.client.Client',
}


def make_client(instance):
    """Returns a client."""
    nsxclient = utils.get_client_class(
        API_NAME,
        instance._api_version[API_NAME],
        API_VERSIONS)
    LOG.debug('Instantiating vmware nsx client: %s', nsxclient)

    client = nsxclient(session=instance.session,
                       region_name=instance._region_name,
                       endpoint_type=instance._interface,
                       insecure=instance._insecure,
                       ca_cert=instance._cacert)
    return client


def build_option_parser(parser):
    """Hook to add global options"""

    return parser
