# Copyright (c) 2013 OpenStack Foundation
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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class ExtensionDriver(object):
    """Define stable abstract interface for extension drivers.
    An extension driver extends the core resources implemented by the
    plugin with additional attributes. Methods that process create
    and update operations for these resources validate and persist
    values for extended attributes supplied through the API. Other
    methods extend the resource dictionaries returned from the API
    operations with the values of the extended attributes.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.
        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    @property
    def extension_alias(self):
        """Supported extension alias.
        Return the alias identifying the core API extension supported
        by this driver. Do not declare if API extension handling will
        be left to a service plugin, and we just need to provide
        core resource extension and updates.
        """
        pass

    def process_create_network(self, plugin_context, data, result):
        """Process extended attributes for create network.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming network data
        :param result: network dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and persist any extended network attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_create_subnet(self, plugin_context, data, result):
        """Process extended attributes for create subnet.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming subnet data
        :param result: subnet dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and persist any extended subnet attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_create_port(self, plugin_context, data, result):
        """Process extended attributes for create port.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming port data
        :param result: port dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and persist any extended port attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_network(self, plugin_context, data, result):
        """Process extended attributes for update network.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming network data
        :param result: network dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and update any extended network attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def process_update_subnet(self, plugin_context, data, result):
        """Process extended attributes for update subnet.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming subnet data
        :param result: subnet dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and update any extended subnet attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def process_update_port(self, plugin_context, data, result):
        """Process extended attributes for update port.
        :param plugin_context: plugin request context
        :param data: dictionary of incoming port data
        :param result: port dictionary to extend
        Called inside transaction context on plugin_context.session to
        validate and update any extended port attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_network_dict(self, session, base_model, result):
        """Add extended attributes to network dictionary.
        :param session: database session
        :param base_model: network model data
        :param result: network dictionary to extend
        Called inside transaction context on session to add any
        extended attributes defined by this driver to a network
        dictionary to be used for driver calls and/or
        returned as the result of a network operation.
        """
        pass

    def extend_subnet_dict(self, session, base_model, result):
        """Add extended attributes to subnet dictionary.
        :param session: database session
        :param base_model: subnet model data
        :param result: subnet dictionary to extend
        Called inside transaction context on session to add any
        extended attributes defined by this driver to a subnet
        dictionary to be used for driver calls and/or
        returned as the result of a subnet operation.
        """
        pass

    def extend_port_dict(self, session, base_model, result):
        """Add extended attributes to port dictionary.
        :param session: database session
        :param base_model: port model data
        :param result: port dictionary to extend
        Called inside transaction context on session to add any
        extended attributes defined by this driver to a port
        dictionary to be used for driver calls
        and/or returned as the result of a port operation.
        """
        pass
