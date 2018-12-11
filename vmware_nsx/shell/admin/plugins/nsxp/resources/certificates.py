# Copyright 2018 VMware, Inc.  All rights reserved.
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

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.common import v3_common_cert
from vmware_nsx.shell import resources as shell

from neutron_lib.callbacks import registry
from oslo_config import cfg


@admin_utils.output_header
def generate_cert(resource, event, trigger, **kwargs):
    """Generate self signed client certificate and private key
    """
    return v3_common_cert.generate_cert(cfg.CONF.nsx_p, **kwargs)


@admin_utils.output_header
def delete_cert(resource, event, trigger, **kwargs):
    """Delete client certificate and private key """
    return v3_common_cert.delete_cert(cfg.CONF.nsx_p, **kwargs)


@admin_utils.output_header
def show_cert(resource, event, trigger, **kwargs):
    """Show client certificate details """
    return v3_common_cert.show_cert(cfg.CONF.nsx_p, **kwargs)


@admin_utils.output_header
def import_cert(resource, event, trigger, **kwargs):
    """Import client certificate that was generated externally"""
    return v3_common_cert.import_cert(cfg.CONF.nsx_p, **kwargs)


@admin_utils.output_header
def show_nsx_certs(resource, event, trigger, **kwargs):
    """Show client certificates associated with openstack identity in NSX"""
    return v3_common_cert.show_nsx_certs(cfg.CONF.nsx_p, **kwargs)


registry.subscribe(generate_cert,
                   constants.CERTIFICATE,
                   shell.Operations.GENERATE.value)

registry.subscribe(show_cert,
                   constants.CERTIFICATE,
                   shell.Operations.SHOW.value)

registry.subscribe(delete_cert,
                   constants.CERTIFICATE,
                   shell.Operations.CLEAN.value)

registry.subscribe(import_cert,
                   constants.CERTIFICATE,
                   shell.Operations.IMPORT.value)

registry.subscribe(show_nsx_certs,
                   constants.CERTIFICATE,
                   shell.Operations.NSX_LIST.value)
