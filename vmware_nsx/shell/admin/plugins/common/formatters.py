# Copyright 2015 VMware, Inc.  All rights reserved.
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
#     under the License.

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

import prettytable

LOG = logging.getLogger(__name__)


def output_formatter(resource_name, resources_list, attrs):
    """Method to format the output response from NSX/Neutron.

    Depending on the --fmt cli option we format the output as
    JSON or as a table.
    """
    LOG.info('%(resource_name)s', {'resource_name': resource_name})
    if not resources_list:
        LOG.info('No resources found')
        return ''

    fmt = cfg.CONF.fmt
    if fmt == 'psql':
        tableout = prettytable.PrettyTable(attrs)
        tableout.padding_width = 1
        tableout.align = "l"
        for resource in resources_list:
            resource_list = []
            for attr in attrs:
                resource_list.append(resource.get(attr))
            tableout.add_row(resource_list)
        return tableout

    elif fmt == 'json':
        js_output = {}
        js_output[resource_name] = []
        for resource in resources_list:
            result = {}
            for attr in attrs:
                result[attr] = resource[attr]
            js_output[resource_name].append(result)
        return jsonutils.dumps(js_output, sort_keys=True, indent=4)


def tabulate_results(data):
    """Method to format the data in a tabular format.

    Expects a list of tuple with the first tuple in the list; being treated as
    column headers.
    """
    columns = data.pop(0)
    table = prettytable.PrettyTable(["%s" % col for col in columns])
    for contents in data:
        table.add_row(["%s" % col for col in contents])
    return table
