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

import abc

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import availability_zone as az_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc

DEFAULT_NAME = 'default'


class ConfiguredAvailabilityZone(object):

    def __init__(self, config_line, default_name=DEFAULT_NAME):
        self.name = ""
        self.init_defaults()
        self._is_default = False
        if config_line and ':' in config_line:
            # Older configuration - each line contains all the relevant
            # values for one availability zones, separated by ':'
            values = config_line.split(':')
            self.name = values[0]
            self._validate_zone_name(self.name)
            self.init_from_config_line(config_line)
        elif config_line:
            # Newer configuration - the name of the availability zone can be
            # used to get the rest of the configuration for this AZ
            self.name = config_line
            self._validate_zone_name(config_line)
            self.init_from_config_section(self.name)
        else:
            # Default zone configuration
            self.name = default_name
            self._is_default = True

    def is_default(self):
        return self._is_default

    def _validate_zone_name(self, config_line):
        if len(self.name) > 36:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="availability_zones",
                opt_value=config_line,
                reason=_("Maximum name length is 36"))

    @abc.abstractmethod
    def init_from_config_line(self, config_values):
        pass

    @abc.abstractmethod
    def init_from_config_section(self, az_name):
        pass

    @abc.abstractmethod
    def init_defaults(self):
        pass


class ConfiguredAvailabilityZones(object):

    default_name = DEFAULT_NAME

    def __init__(self, az_conf, az_class, default_availability_zones=None):
        self.availability_zones = {}

        # Add the configured availability zones
        for az in az_conf:
            obj = az_class(az)
            self.availability_zones[obj.name] = obj

        # add a default entry
        obj = az_class(None, default_name=self.default_name)
        self.availability_zones[obj.name] = obj

        # validate the default az:
        if default_availability_zones:
            # we support only 1 default az
            if len(default_availability_zones) > 1:
                raise nsx_exc.NsxInvalidConfiguration(
                    opt_name="default_availability_zones",
                    opt_value=default_availability_zones,
                    reason=_("The NSX plugin supports only 1 default AZ"))
            default_az_name = default_availability_zones[0]
            if (default_az_name not in self.availability_zones):
                raise nsx_exc.NsxInvalidConfiguration(
                    opt_name="default_availability_zones",
                    opt_value=default_availability_zones,
                    reason=_("The default AZ is not defined in the NSX "
                             "plugin"))
            else:
                self._default_az = self.availability_zones[default_az_name]
        else:
            self._default_az = self.availability_zones[self.default_name]

    def get_availability_zone(self, name):
        """Return an availability zone object by its name
        """
        if name in self.availability_zones.keys():
            return self.availability_zones[name]
        return self.get_default_availability_zone()

    def get_default_availability_zone(self):
        """Return the default availability zone object
        """
        return self._default_az

    def list_availability_zones(self):
        """Return a list of availability zones names
        """
        return self.availability_zones.keys()

    def list_availability_zones_objects(self):
        """Return a list of availability zones objects
        """
        return self.availability_zones.values()


class NSXAvailabilityZonesPluginCommon(object):

    @abc.abstractmethod
    def init_availability_zones(self):
        # To be initialized by the real plugin
        self._availability_zones_data = None

    def get_azs_list(self):
        return self._availability_zones_data.list_availability_zones_objects()

    def get_azs_names(self):
        return self._availability_zones_data.list_availability_zones()

    def validate_obj_azs(self, availability_zones):
        """Verify that the availability zones exist, and only 1 hint
        was set.
        """
        # For now we support only 1 hint per network/router
        # TODO(asarfaty): support multiple hints
        if len(availability_zones) > 1:
            err_msg = _("Can't use multiple availability zone hints")
            raise n_exc.InvalidInput(error_message=err_msg)

        # check that all hints appear in the predefined list of availability
        # zones
        diff = (set(availability_zones) - set(self.get_azs_names()))
        if diff:
            raise az_exc.AvailabilityZoneNotFound(
                availability_zone=diff.pop())

    def get_az_by_hint(self, hint):
        az = self._availability_zones_data.get_availability_zone(hint)
        if not az:
            raise az_def.AvailabilityZoneNotFound(availability_zone=hint)
        return az

    def get_default_az(self):
        return self._availability_zones_data.get_default_availability_zone()

    def get_obj_az_by_hints(self, obj):
        if az_def.AZ_HINTS in obj:
            for hint in obj[az_def.AZ_HINTS]:
                # For now we use only the first hint
                return self.get_az_by_hint(hint)

        # return the default
        return self.get_default_az()

    def get_network_az(self, network):
        return self.get_obj_az_by_hints(network)

    def get_router_az(self, router):
        return self.get_obj_az_by_hints(router)
