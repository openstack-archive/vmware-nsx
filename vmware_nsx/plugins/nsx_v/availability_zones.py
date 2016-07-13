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

from neutron_lib import exceptions as n_exc
from oslo_config import cfg

from vmware_nsx._i18n import _

DEFAULT_NAME = 'default'


class ConfiguredAvailabilityZone(object):

    def __init__(self, config_line):
        if config_line:
            values = config_line.split(':')
            if len(values) < 3 or len(values) > 4:
                raise n_exc.Invalid(_("Invalid availability zones format"))

            self.name = values[0]
            # field name limit in the DB
            if len(self.name) > 36:
                raise n_exc.Invalid(_("Invalid availability zone name %s: "
                                      "max name length is 36"), self.name)

            self.resource_pool = values[1]
            self.datastore_id = values[2]
            self.ha_datastore_id = values[3] if len(values) == 4 else None
        else:
            # use the default configuration
            self.name = DEFAULT_NAME
            self.resource_pool = cfg.CONF.nsxv.resource_pool_id
            self.datastore_id = cfg.CONF.nsxv.datastore_id
            self.ha_datastore_id = cfg.CONF.nsxv.ha_datastore_id


class ConfiguredAvailabilityZones(object):

    def __init__(self):
        self.availability_zones = {}

        # Add the configured availability zones
        for az in cfg.CONF.nsxv.availability_zones:
            obj = ConfiguredAvailabilityZone(az)
            self.availability_zones[obj.name] = obj
            # DEBUG ADIT - name max len 36 (DB)

        # add a default entry
        obj = ConfiguredAvailabilityZone(None)
        self.availability_zones[obj.name] = obj

    def get_resources(self):
        """Return a list of all the resources in all the availability zones
        """
        resources = []
        for az in self.availability_zones.values():
            resources.append(az.resource_pool)
            resources.append(az.datastore_id)
            if az.ha_datastore_id:
                resources.append(az.ha_datastore_id)
        return resources

    def get_availability_zone(self, name):
        """Return an availability zone object by its name
        """
        if name in self.availability_zones.keys():
            return self.availability_zones[name]

    def get_default_availability_zone(self):
        """Return the default availability zone object
        """
        return self.availability_zones[DEFAULT_NAME]

    def list_availability_zones(self):
        """Return a list of availability zones names
        """
        return self.availability_zones.keys()
