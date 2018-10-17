# Copyright 2018 VMware Inc
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

import optparse

import sqlalchemy as sa

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config


class NeutronNsxDB(object):
    def __init__(self, db_connection):
        super(NeutronNsxDB, self).__init__()
        engine = sa.create_engine(db_connection)
        self.session = sa.orm.session.sessionmaker()(bind=engine)

    def query_all(self, column, model):
        return list(set([r[column] for r in self.session.query(model).all()]))


class NSXClient(object):
    """Base NSX REST client"""
    API_VERSION = "v1"
    NULL_CURSOR_PREFIX = '0000'

    def __init__(self, host, username, password, db_connection):
        self.host = host
        self.username = username
        self.password = password
        self.neutron_db = (NeutronNsxDB(db_connection)
                           if db_connection else None)

        nsxlib_config = config.NsxLibConfig(
            username=self.username,
            password=self.password,
            nsx_api_managers=[self.host],
            # allow admin user to delete entities created
            # under openstack principal identity
            allow_overwrite_header=True)
        self.nsxlib = v3.NsxPolicyLib(nsxlib_config)

    def cleanup_all(self):
        """
        Cleanup steps:
            - Firewall sections
            - NSGroups
            - VPN objects
            - Loadbalancer objects
            - Logical router and their ports
            - Logical Tier 0 routers ports
            - Logical switch ports
            - Logical switches
            - DHCP servers
            - Switching profiles
        """
        return


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--policy-ip", dest="policy_ip", help="NSX Policy IP "
                                                            "address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Policy username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Policy password")
    parser.add_option("--db-connection", default="", dest="db_connection",
                      help=("When set, cleaning only backend resources that "
                            "have db record."))
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.policy_ip, options.username,
                           options.password, options.db_connection)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
