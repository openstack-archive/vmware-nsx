# Copyright (c) 2016 IBM
# Copyright (c) 2017 VMware, Inc.
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

from neutron_lib.api.definitions import dns
from neutron_lib.api import validators
from neutron_lib import context as n_context
from neutron_lib.exceptions import dns as dns_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from neutron.extensions import availability_zone as az_ext
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.services.externaldns import driver

from vmware_nsx.common import driver_api
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az

LOG = logging.getLogger(__name__)
DNS_DOMAIN_DEFAULT = 'openstacklocal.'


# TODO(asarfaty) use dns-domain/nameserver from network az instead of global
class DNSExtensionDriver(driver_api.ExtensionDriver):
    _supported_extension_alias = 'dns-integration'

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, plugin_context, request_data, db_data):
        dns_domain = request_data.get(dns.DNSDOMAIN)
        if not validators.is_attr_set(dns_domain):
            return

        if dns_domain:
            net_obj.NetworkDNSDomain(plugin_context,
                                     network_id=db_data['id'],
                                     dns_domain=dns_domain).create()
        db_data[dns.DNSDOMAIN] = dns_domain

    def process_update_network(self, plugin_context, request_data, db_data):
        new_value = request_data.get(dns.DNSDOMAIN)
        if not validators.is_attr_set(new_value):
            return

        current_dns_domain = db_data.get(dns.DNSDOMAIN)
        if current_dns_domain == new_value:
            return

        net_id = db_data['id']
        if current_dns_domain:
            net_dns_domain = net_obj.NetworkDNSDomain.get_object(
                plugin_context,
                network_id=net_id)
            if new_value:
                net_dns_domain['dns_domain'] = new_value
                db_data[dns.DNSDOMAIN] = new_value
                net_dns_domain.update()
            else:
                net_dns_domain.delete()
                db_data[dns.DNSDOMAIN] = ''
        elif new_value:
            net_obj.NetworkDNSDomain(plugin_context,
                                     network_id=net_id,
                                     dns_domain=new_value).create()
            db_data[dns.DNSDOMAIN] = new_value

    def process_create_port(self, plugin_context, request_data, db_data):
        if not request_data.get(dns.DNSNAME):
            return
        dns_name, is_dns_domain_default = self._get_request_dns_name(
            request_data, db_data['network_id'], plugin_context)
        if is_dns_domain_default:
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        if self.external_dns_not_needed(
                plugin_context, network) or not network[dns.DNSDOMAIN]:
            current_dns_name = ''
            current_dns_domain = ''
        else:
            current_dns_name = dns_name
            current_dns_domain = network[dns.DNSDOMAIN]
        port_obj.PortDNS(plugin_context,
                         port_id=db_data['id'],
                         current_dns_name=current_dns_name,
                         current_dns_domain=current_dns_domain,
                         previous_dns_name='',
                         previous_dns_domain='',
                         dns_name=dns_name).create()

    def _update_dns_db(self, dns_name, dns_domain, db_data,
                      plugin_context, has_fixed_ips):
        dns_data_db = port_obj.PortDNS.get_object(
            plugin_context,
            port_id=db_data['id'])
        if dns_data_db:
            is_dns_name_changed = (dns_name is not None and
                    dns_data_db['current_dns_name'] != dns_name)

            if is_dns_name_changed or (has_fixed_ips and
                                       dns_data_db['current_dns_name']):
                dns_data_db['previous_dns_name'] = (
                    dns_data_db['current_dns_name'])
                dns_data_db['previous_dns_domain'] = (
                    dns_data_db['current_dns_domain'])
                if is_dns_name_changed:
                    dns_data_db[dns.DNSNAME] = dns_name
                    dns_data_db['current_dns_name'] = dns_name
                    if dns_name:
                        dns_data_db['current_dns_domain'] = dns_domain
                    else:
                        dns_data_db['current_dns_domain'] = ''

            dns_data_db.update()
            return dns_data_db
        if dns_name:
            dns_data_db = port_obj.PortDNS(plugin_context,
                                           port_id=db_data['id'],
                                           current_dns_name=dns_name,
                                           current_dns_domain=dns_domain,
                                           previous_dns_name='',
                                           previous_dns_domain='',
                                           dns_name=dns_name)
            dns_data_db.create()
        return dns_data_db

    def process_update_port(self, plugin_context, request_data, db_data):
        dns_name = request_data.get(dns.DNSNAME)
        has_fixed_ips = 'fixed_ips' in request_data
        if dns_name is None and not has_fixed_ips:
            return
        if dns_name is not None:
            dns_name, is_dns_domain_default = self._get_request_dns_name(
                request_data, db_data['network_id'], plugin_context)
            if is_dns_domain_default:
                self._extend_port_dict(db_data, db_data, None, plugin_context)
                return
        network = self._get_network(plugin_context, db_data['network_id'])
        dns_domain = network[dns.DNSDOMAIN]
        dns_data_db = None
        if not dns_domain or self.external_dns_not_needed(plugin_context,
                                                          network):
            # No need to update external DNS service. Only process the port's
            # dns_name attribute if necessary
            if dns_name is not None:
                dns_data_db = self._process_only_dns_name_update(
                    plugin_context, db_data, dns_name)
        else:
            dns_data_db = self._update_dns_db(dns_name, dns_domain, db_data,
                                              plugin_context, has_fixed_ips)
        self._extend_port_dict(db_data, db_data, dns_data_db, plugin_context)

    def _process_only_dns_name_update(self, plugin_context, db_data, dns_name):
        dns_data_db = port_obj.PortDNS.get_object(
            plugin_context,
            port_id=db_data['id'])
        if dns_data_db:
            dns_data_db['dns_name'] = dns_name
            dns_data_db.update()
            return dns_data_db
        if dns_name:
            dns_data_db = port_obj.PortDNS(plugin_context,
                                           port_id=db_data['id'],
                                           current_dns_name='',
                                           current_dns_domain='',
                                           previous_dns_name='',
                                           previous_dns_domain='',
                                           dns_name=dns_name)
            dns_data_db.create()
        return dns_data_db

    def external_dns_not_needed(self, context, network):
        """Decide if ports in network need to be sent to the DNS service.

        :param context: plugin request context
        :param network: network dictionary
        :return: True or False
        """
        pass

    def extend_network_dict(self, session, db_data, response_data):
        response_data[dns.DNSDOMAIN] = ''
        if db_data.dns_domain:
            response_data[dns.DNSDOMAIN] = db_data.dns_domain[dns.DNSDOMAIN]
        return response_data

    def _get_dns_domain(self, network_id, context=None):
        if not cfg.CONF.dns_domain:
            return ''
        if cfg.CONF.dns_domain.endswith('.'):
            return cfg.CONF.dns_domain
        return '%s.' % cfg.CONF.dns_domain

    def _get_request_dns_name(self, port, network_id, context):
        dns_domain = self._get_dns_domain(network_id, context)
        if ((dns_domain and dns_domain != DNS_DOMAIN_DEFAULT)):
            return (port.get(dns.DNSNAME, ''), False)
        return ('', True)

    def _get_request_dns_name_and_domain_name(self, dns_data_db,
                                              network_id, context):
        dns_domain = self._get_dns_domain(network_id, context)
        dns_name = ''
        if ((dns_domain and dns_domain != DNS_DOMAIN_DEFAULT)):
            if dns_data_db:
                dns_name = dns_data_db.dns_name
        return dns_name, dns_domain

    def _get_dns_names_for_port(self, ips, dns_data_db, network_id, context):
        dns_assignment = []
        dns_name, dns_domain = self._get_request_dns_name_and_domain_name(
            dns_data_db, network_id, context)
        for ip in ips:
            if dns_name:
                hostname = dns_name
                fqdn = dns_name
                if not dns_name.endswith('.'):
                    fqdn = '%s.%s' % (dns_name, dns_domain)
            else:
                hostname = 'host-%s' % ip['ip_address'].replace(
                    '.', '-').replace(':', '-')
                fqdn = hostname
                if dns_domain:
                    fqdn = '%s.%s' % (hostname, dns_domain)
            dns_assignment.append({'ip_address': ip['ip_address'],
                                   'hostname': hostname,
                                   'fqdn': fqdn})
        return dns_assignment

    def _get_dns_name_for_port_get(self, port, dns_data_db, context):
        if port['fixed_ips']:
            return self._get_dns_names_for_port(
                port['fixed_ips'], dns_data_db,
                port['network_id'], context)
        return []

    def _extend_port_dict(self, db_data, response_data,
                          dns_data_db, context=None):
        if not dns_data_db:
            response_data[dns.DNSNAME] = ''
        else:
            response_data[dns.DNSNAME] = dns_data_db[dns.DNSNAME]
        response_data['dns_assignment'] = self._get_dns_name_for_port_get(
            db_data, dns_data_db, context)
        return response_data

    def extend_port_dict(self, session, db_data, response_data):
        dns_data_db = db_data.dns
        return self._extend_port_dict(db_data, response_data, dns_data_db)

    def _get_network(self, context, network_id):
        plugin = directory.get_plugin()
        return plugin.get_network(context, network_id)


class DNSExtensionDriverNSXv(DNSExtensionDriver):

    def initialize(self):
        LOG.info("DNSExtensionDriverNSXv initialization complete")

    def external_dns_not_needed(self, context, network):
        dns_driver = _get_dns_driver()
        if not dns_driver:
            return True
        if network['router:external']:
            return True
        return False


class DNSExtensionDriverNSXv3(DNSExtensionDriver):

    def initialize(self):
        self._availability_zones = nsx_az.NsxV3AvailabilityZones()
        LOG.info("DNSExtensionDriverNSXv3 initialization complete")

    def _get_network_az(self, network_id, context):
        if not context:
            context = n_context.get_admin_context()
        network = self._get_network(context, network_id)
        if az_ext.AZ_HINTS in network and network[az_ext.AZ_HINTS]:
            az_name = network[az_ext.AZ_HINTS][0]
            return self._availability_zones.get_availability_zone(az_name)
        return self._availability_zones.get_default_availability_zone()

    def _get_dns_domain(self, network_id, context=None):
        # try to get the dns-domain from the specific availability zone
        # of this network
        az = self._get_network_az(network_id, context)
        if az.dns_domain:
            dns_domain = az.dns_domain
        elif cfg.CONF.nsx_v3.dns_domain:
            dns_domain = cfg.CONF.nsx_v3.dns_domain
        elif cfg.CONF.dns_domain:
            dns_domain = cfg.CONF.dns_domain
        else:
            return ''
        if dns_domain.endswith('.'):
            return dns_domain
        return '%s.' % dns_domain

    def external_dns_not_needed(self, context, network):
        dns_driver = _get_dns_driver()
        if not dns_driver:
            return True
        if network['router:external']:
            return True
        return False


DNS_DRIVER = None


def _get_dns_driver():
    global DNS_DRIVER
    if DNS_DRIVER:
        return DNS_DRIVER
    if not cfg.CONF.external_dns_driver:
        return
    try:
        DNS_DRIVER = driver.ExternalDNSService.get_instance()
        LOG.debug("External DNS driver loaded: %s",
                  cfg.CONF.external_dns_driver)
        return DNS_DRIVER
    except ImportError:
        LOG.exception("ImportError exception occurred while loading "
                      "the external DNS service driver")
        raise dns_exc.ExternalDNSDriverNotFound(
            driver=cfg.CONF.external_dns_driver)
