# Copyright 2016 VMware, Inc.
# All rights reserved.
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
from osc_lib import utils as osc_utils


cached_extensions = None


def get_extensions(client_manager):
    """Return a list of all current extensions aliases"""
    # Return previously calculated results
    global cached_extensions
    if cached_extensions is not None:
        return cached_extensions
    # Get supported extensions from the manager
    data = client_manager.network.extensions()
    extensions = []
    for s in data:
        prop = osc_utils.get_item_properties(
            s, ('Alias',), formatters={})
        extensions.append(prop[0])
    # Save the results in the global cache
    cached_extensions = extensions
    return extensions
