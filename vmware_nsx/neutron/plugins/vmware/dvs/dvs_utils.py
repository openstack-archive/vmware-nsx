# Copyright 2014 VMware, Inc.
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

from oslo.config import cfg
from oslo.vmware import api

dvs_opts = [
    cfg.StrOpt('host_ip',
               help='Hostname or IP address for connection to VMware VC '
                    'host.'),
    cfg.IntOpt('host_port', default=443,
               help='Port for connection to VMware VC host.'),
    cfg.StrOpt('host_username',
               help='Username for connection to VMware VC host.'),
    cfg.StrOpt('host_password',
               help='Password for connection to VMware VC host.',
               secret=True),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
                    'socket error, etc.'),
    cfg.StrOpt('dvs_name',
               help='The name of the preconfigured DVS.'),
]

CONF = cfg.CONF
CONF.register_opts(dvs_opts, 'dvs')


def dvs_is_enabled():
    """Returns the configured DVS status."""
    return bool(CONF.dvs.host_ip and CONF.dvs.host_username and
                CONF.dvs.host_password and CONF.dvs.dvs_name)


def dvs_create_session():
    return api.VMwareAPISession(CONF.dvs.host_ip,
                                CONF.dvs.host_username,
                                CONF.dvs.host_password,
                                CONF.dvs.api_retry_count,
                                CONF.dvs.task_poll_interval,
                                port=CONF.dvs.host_port)


def dvs_name_get():
    return CONF.dvs.dvs_name
