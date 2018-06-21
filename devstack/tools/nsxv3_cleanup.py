# Copyright 2015 VMware Inc
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

from vmware_nsx.db import nsx_models
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import nsx_constants


class NeutronNsxDB(object):
    def __init__(self, db_connection):
        super(NeutronNsxDB, self).__init__()
        engine = sa.create_engine(db_connection)
        self.session = sa.orm.session.sessionmaker()(bind=engine)

    def query_all(self, column, model):
        return list(set([r[column] for r in self.session.query(model).all()]))

    def get_logical_ports(self):
        return self.query_all('nsx_port_id',
                              nsx_models.NeutronNsxPortMapping)

    def get_nsgroups(self):
        return self.query_all('nsx_id',
                              nsx_models.NeutronNsxSecurityGroupMapping)

    def get_firewall_sections(self):
        return self.query_all('nsx_id',
                              nsx_models.NeutronNsxFirewallSectionMapping)

    def get_logical_routers(self):
        return self.query_all('nsx_id',
                              nsx_models.NeutronNsxRouterMapping)

    def get_logical_switches(self):
        return self.query_all('nsx_id',
                              nsx_models.NeutronNsxNetworkMapping)

    def get_logical_dhcp_servers(self):
        return self.query_all('nsx_service_id',
                              nsx_models.NeutronNsxServiceBinding)

    def get_vpn_objects(self, column_name):
        return self.query_all(column_name,
                              nsx_models.NsxVpnConnectionMapping)

    def get_db_objects_by_table_and_column(self, db_table, db_column):
        return self.query_all(db_column, db_table)


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
        self.nsxlib = v3.NsxLib(nsxlib_config)

    def get_transport_zones(self):
        """
        Retrieve all transport zones
        """
        return self.nsxlib.transport_zone.list()['results']

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.nsxlib.logical_port.list()['results']

    def get_os_logical_ports(self):
        """
        Retrieve all logical ports created from OpenStack
        """
        lports = self.get_os_resources(
            self.get_logical_ports())
        if self.neutron_db:
            db_lports = self.neutron_db.get_logical_ports()
            lports = [lp for lp in lports if lp['id'] in db_lports]
        return lports

    def update_logical_port_attachment(self, lports):
        """
        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            try:
                self.nsxlib.logical_port.update(
                    p['id'], None, attachment_type=None)
            except Exception as e:
                print("ERROR: Failed to update lport %s: %s" % p['id'], e)

    def _remove_port_from_exclude_list(self, p):
        try:
            self.nsxlib.firewall_section.remove_member_from_fw_exclude_list(
                p['id'], None)
        except Exception:
            pass

    def _cleanup_logical_ports(self, lports):
        # logical port vif detachment
        self.update_logical_port_attachment(lports)
        for p in lports:
            # delete this port from the exclude list (if in it)
            self._remove_port_from_exclude_list(p)
            try:
                self.nsxlib.logical_port.delete(p['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical port %s, error %s" %
                      (p['id'], e))
            else:
                print("Successfully deleted logical port %s" % p['id'])

    def cleanup_os_logical_ports(self):
        """
        Delete all logical ports created by OpenStack
        """
        os_lports = self.get_os_logical_ports()
        print("Number of OS Logical Ports to be deleted: %s" % len(os_lports))
        self._cleanup_logical_ports(os_lports)

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-api-version' in tag.values()]
        return os_resources

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        return self.nsxlib.logical_switch.list()['results']

    def get_os_logical_switches(self):
        """
        Retrieve all logical switches created from OpenStack
        """
        lswitches = self.get_os_resources(
            self.get_logical_switches())

        if self.neutron_db:
            db_lswitches = self.neutron_db.get_logical_switches()
            lswitches = [ls for ls in lswitches
                         if ls['id'] in db_lswitches]
        return lswitches

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] == ls_id]

    def cleanup_os_logical_switches(self):
        """
        Delete all logical switches created from OpenStack
        """
        lswitches = self.get_os_logical_switches()
        print("Number of OS Logical Switches to be deleted: %s" %
              len(lswitches))
        for ls in lswitches:
            # Check if there are still ports on switch and blow them away
            # An example here is a metadata proxy port (this is not stored
            # in the DB so we are unable to delete it when reading ports
            # from the DB)
            lports = self.get_lswitch_ports(ls['id'])
            if lports:
                print("Number of orphan OS Logical Ports to be "
                      "deleted: %s" % len(lports))
                self._cleanup_logical_ports(lports)

            try:
                self.nsxlib.logical_switch.delete(ls['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical switch %s-%s, "
                      "error %s" % (ls['display_name'], ls['id'], e))
            else:
                print("Successfully deleted logical switch %s-%s" %
                      (ls['display_name'], ls['id']))

    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        return self.nsxlib.firewall_section.list()

    def get_os_firewall_sections(self):
        """
        Retrieve all firewall sections created from OpenStack
        """
        fw_sections = self.get_os_resources(
            self.get_firewall_sections())
        if self.neutron_db:
            db_sections = self.neutron_db.get_firewall_sections()
            fw_sections = [fws for fws in fw_sections
                           if fws['id'] in db_sections]
        return fw_sections

    def cleanup_os_firewall_sections(self):
        """
        Cleanup all firewall sections created from OpenStack
        """
        fw_sections = self.get_os_firewall_sections()
        print("Number of OS Firewall Sections to be deleted: %s" %
              len(fw_sections))
        for fw in fw_sections:
            try:
                self.nsxlib.firewall_section.delete(fw['id'])
            except Exception as e:
                print("Failed to delete firewall section %s: %s" %
                      (fw['display_name'], e))
            else:
                print("Successfully deleted firewall section %s" %
                      fw['display_name'])

    def get_ns_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        backend_groups = self.nsxlib.ns_group.list()
        ns_groups = self.get_os_resources(backend_groups)
        if self.neutron_db:
            db_nsgroups = self.neutron_db.get_nsgroups()
            ns_groups = [nsg for nsg in ns_groups
                         if nsg['id'] in db_nsgroups]
        return ns_groups

    def cleanup_os_ns_groups(self):
        """
        Cleanup all NSGroups created from OpenStack plugin
        """
        ns_groups = self.get_ns_groups()
        print("Number of OS NSGroups to be deleted: %s" % len(ns_groups))
        for nsg in ns_groups:
            try:
                self.nsxlib.ns_group.delete(nsg['id'])
            except Exception as e:
                print("Failed to delete NSGroup: %s: %s" %
                      (nsg['display_name'], e))
            else:
                print("Successfully deleted NSGroup: %s" %
                      nsg['display_name'])

    def get_switching_profiles(self):
        """
        Retrieve all Switching Profiles on NSX backend
        """
        return self.nsxlib.switching_profile.list()['results']

    def get_os_switching_profiles(self):
        """
        Retrieve all Switching Profiles created from OpenStack
        """
        sw_profiles = self.get_os_resources(
            self.get_switching_profiles())
        if self.neutron_db:
            sw_profiles = []
        return sw_profiles

    def cleanup_os_switching_profiles(self):
        """
        Cleanup all Switching Profiles created from OpenStack plugin
        """
        sw_profiles = self.get_os_switching_profiles()
        print("Number of OS SwitchingProfiles to be deleted: %s" %
              len(sw_profiles))
        for swp in sw_profiles:
            try:
                self.nsxlib.switching_profile.delete(swp['id'])
            except Exception as e:
                print("Failed to delete Switching Profile: %s: %s" %
                      (swp['display_name'], e))
            else:
                print("Successfully deleted Switching Profile: %s" %
                      swp['display_name'])

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        lrouters = self.nsxlib.logical_router.list(
            router_type=tier)['results']

        if self.neutron_db:
            db_routers = self.neutron_db.get_logical_routers()
            lrouters = [lr for lr in lrouters
                        if lr['id'] in db_routers]
        return lrouters

    def get_os_logical_routers(self):
        """
        Retrieve all logical routers created from Neutron NSXv3 plugin
        """
        lrouters = self.get_logical_routers()
        return self.get_os_resources(lrouters)

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        return self.nsxlib.logical_router_port.get_by_router_id(lrouter['id'])

    def get_os_logical_router_ports(self, lrouter):
        """
        Retrieve all logical router ports created from Neutron NSXv3 plugin
        """
        lports = self.get_logical_router_ports(lrouter)
        return self.get_os_resources(lports)

    def cleanup_logical_router_ports(self, lrouter):
        """
        Cleanup all logical ports on a logical router
        """
        lports = self.get_os_logical_router_ports(lrouter)
        for lp in lports:
            try:
                self.nsxlib.logical_router_port.delete(lp['id'])
            except Exception as e:
                print("Failed to delete logical router port %s-%s, "
                      "and response is %s" %
                      (lp['display_name'], lp['id'], e))
            else:
                print("Successfully deleted logical router port %s-%s" %
                      (lp['display_name'], lp['id']))

    def cleanup_os_logical_routers(self):
        """
        Delete all logical routers created from OpenStack
        To delete a logical router, we need to delete all logical
        ports on the router first.
        """
        lrouters = self.get_os_logical_routers()
        print("Number of OS Logical Routers to be deleted: %s" %
              len(lrouters))
        for lr in lrouters:
            self.cleanup_logical_router_ports(lr)
            self.cleanup_logical_router_vpn_sess(lr)
            try:
                self.nsxlib.logical_router.delete(lr['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical router %s-%s, "
                      "error %s" % (lr['display_name'], lr['id'], e))
            else:
                print("Successfully deleted logical router %s-%s" %
                      (lr['display_name'], lr['id']))

    def cleanup_os_tier0_logical_ports(self):
        """
        Delete all TIER0 logical router ports created from OpenStack
        """
        tier0_routers = self.get_logical_routers(tier='TIER0')
        for lr in tier0_routers:
            self.cleanup_logical_router_ports(lr)

    def get_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers on NSX backend
        """
        return self.nsxlib.dhcp_server.list()['results']

    def get_os_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers created from OpenStack
        """
        dhcp_servers = self.get_os_resources(
            self.get_logical_dhcp_servers())

        if self.neutron_db:
            db_dhcp_servers = self.neutron_db.get_logical_dhcp_servers()
            dhcp_servers = [srv for srv in dhcp_servers
                            if srv['id'] in db_dhcp_servers]
        return dhcp_servers

    def cleanup_os_logical_dhcp_servers(self):
        """
        Cleanup all logical DHCP servers created from OpenStack plugin
        """
        dhcp_servers = self.get_os_logical_dhcp_servers()
        print("Number of OS Logical DHCP Servers to be deleted: %s" %
              len(dhcp_servers))
        for server in dhcp_servers:
            try:
                self.nsxlib.dhcp_server.delete(server['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical DHCP server %s, "
                      "error %s" % (server['display_name'], e))
            else:
                print("Successfully deleted logical DHCP server %s" %
                      server['display_name'])

    def get_os_vpn_objects(self, nsxlib_class, db_column_name):
        """
        Retrieve all nsx vpn sessions from nsx and OpenStack
        """
        objects = self.get_os_resources(nsxlib_class.list()['results'])
        if self.neutron_db:
            db_objects = self.neutron_db.get_vpn_objects(db_column_name)
            objects = [obj for obj in objects if obj['id'] in db_objects]
        return objects

    def clean_vpn_objects(self, obj_name, nsxlib_class, db_column_name):
        objects = self.get_os_vpn_objects(nsxlib_class, db_column_name)
        print("Number of VPN %(name)ss to be deleted: %(num)s" %
              {'name': obj_name, 'num': len(objects)})
        for obj in objects:
            try:
                nsxlib_class.delete(obj['id'])
            except Exception as e:
                print("ERROR: Failed to delete vpn ipsec %(name)s %(id)s, "
                      "error %(e)s" % {'name': obj_name, 'id': obj['id'],
                                       'e': e})
            else:
                print("Successfully deleted vpn ipsec %(name)s %(id)s" %
                      {'name': obj_name, 'id': obj['id']})

    def cleanup_vpnaas(self):
        """
        Cleanup vpn/ipsec nsx objects
        """
        if not self.nsxlib.feature_supported(nsx_constants.FEATURE_IPSEC_VPN):
            # no vpn support
            return

        self.clean_vpn_objects('session',
                               self.nsxlib.vpn_ipsec.session,
                               'session_id')
        self.clean_vpn_objects('peer endpoint',
                               self.nsxlib.vpn_ipsec.peer_endpoint,
                               'peer_ep_id')
        self.clean_vpn_objects('DPD profile',
                               self.nsxlib.vpn_ipsec.dpd_profile,
                               'dpd_profile_id')
        self.clean_vpn_objects('IKE profile',
                               self.nsxlib.vpn_ipsec.ike_profile,
                               'ike_profile_id')
        self.clean_vpn_objects('tunnel profile',
                               self.nsxlib.vpn_ipsec.tunnel_profile,
                               'ipsec_profile_id')
        #NOTE(asarfaty): The vpn services are not deleted since we have 1 per
        # Tier-0 router, and those can be used outside of openstack too.

    def cleanup_logical_router_vpn_sess(self, lr):
        """
        Cleanup the vpn local session of the logical router
        """
        if not self.nsxlib.feature_supported(nsx_constants.FEATURE_IPSEC_VPN):
            # no vpn support
            return

        # find the router neutron id in its tags
        neutron_id = None
        for tag in lr['tags']:
            if tag.get('scope') == 'os-neutron-router-id':
                neutron_id = tag.get('tag')
                break

        if not neutron_id:
            return

        tags = [{'scope': 'os-neutron-router-id', 'tag': neutron_id}]
        ep_list = self.nsxlib.search_by_tags(
            tags=tags,
            resource_type=self.nsxlib.vpn_ipsec.local_endpoint.resource_type)
        if ep_list['results']:
            id = ep_list['results'][0]['id']
            try:
                self.nsxlib.vpn_ipsec.local_endpoint.delete(id)
            except Exception as e:
                print("ERROR: Failed to delete vpn ipsec local endpoint %s, "
                      "error %s" % (id, e))
            else:
                print("Successfully deleted vpn ipsec local endpoint %s" % id)

    def get_os_nsx_objects(self, nsxlib_class, db_table, db_column):
        """
        Retrieve all nsx objects of a given type from the nsx and OpenStack DB
        """
        objects = self.get_os_resources(nsxlib_class.list()['results'])
        if self.neutron_db:
            db_objects = self.neutron_db.get_db_objects_by_table_and_column(
                db_table, db_column)
            objects = [obj for obj in objects if obj['id'] in db_objects]
        return objects

    def clean_lb_objects(self, obj_name, nsxlib_class, objects):
        print("Number of LB %(name)ss to be deleted: %(num)s" %
              {'name': obj_name, 'num': len(objects)})
        for obj in objects:
            try:
                nsxlib_class.delete(obj['id'])
            except Exception as e:
                print("ERROR: Failed to delete LB %(name)s %(id)s, "
                      "error %(e)s" % {'name': obj_name, 'id': obj['id'],
                                       'e': e})
            else:
                print("Successfully deleted LB %(name)s %(id)s" %
                      {'name': obj_name, 'id': obj['id']})

    def cleanup_loadbalancer(self):
        """
        Cleanup LBaaS/Octavia loadbalancer objects
        """
        if not self.nsxlib.feature_supported(
            nsx_constants.FEATURE_LOAD_BALANCER):
            # no LB support
            return

        # lb services
        objects = self.get_os_nsx_objects(self.nsxlib.load_balancer.service,
                                         nsx_models.NsxLbaasLoadbalancer,
                                         'lb_service_id')
        self.clean_lb_objects('service', self.nsxlib.load_balancer.service,
                              objects)

        # listeners
        objects = self.get_os_nsx_objects(
            self.nsxlib.load_balancer.virtual_server,
            nsx_models.NsxLbaasListener, 'lb_vs_id')

        # get a list of application profiles by their virtual servers
        app_profiles = []
        for virtual_server in objects:
            lb_vs = self.nsxlib.load_balancer.virtual_server.get(
                virtual_server['id'])
            if lb_vs.get('application_profile_id'):
                app_profiles.append({'id': lb_vs['application_profile_id']})
        self.clean_lb_objects('listener',
                              self.nsxlib.load_balancer.virtual_server,
                              objects)

        # pools
        objects = self.get_os_nsx_objects(self.nsxlib.load_balancer.pool,
                                         nsx_models.NsxLbaasPool, 'lb_pool_id')
        self.clean_lb_objects('pool', self.nsxlib.load_balancer.pool,
                              objects)

        # health monitors
        objects = self.get_os_nsx_objects(self.nsxlib.load_balancer.monitor,
                                         nsx_models.NsxLbaasMonitor,
                                         'lb_monitor_id')
        self.clean_lb_objects('monitor', self.nsxlib.load_balancer.monitor,
                              objects)

        # application profiles
        self.clean_lb_objects('application-profile',
                              self.nsxlib.load_balancer.application_profile,
                              app_profiles)

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
        self.cleanup_os_firewall_sections()
        self.cleanup_os_ns_groups()
        self.cleanup_vpnaas()
        self.cleanup_loadbalancer()
        self.cleanup_os_logical_routers()
        self.cleanup_os_tier0_logical_ports()
        self.cleanup_os_logical_ports()
        self.cleanup_os_logical_switches()
        self.cleanup_os_logical_dhcp_servers()
        self.cleanup_os_switching_profiles()


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    parser.add_option("--db-connection", default="", dest="db_connection",
                      help=("When set, cleaning only backend resources that "
                            "have db record."))
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.mgr_ip, options.username,
                           options.password, options.db_connection)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
