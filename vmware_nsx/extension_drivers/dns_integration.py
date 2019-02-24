# Copyright (c) 2018 VMware, Inc.
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

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import dns
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib.exceptions import dns as dns_exc
from neutron_lib.objects import registry as obj_reg
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from neutron.services.externaldns import driver

from vmware_nsx.common import driver_api
from vmware_nsx.plugins.nsx_p import availability_zones as nsxp_az
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az

LOG = logging.getLogger(__name__)
DNS_DOMAIN_DEFAULT = 'openstacklocal.'


def _dotted_domain(dns_domain):
    if dns_domain.endswith('.'):
        return dns_domain
    return '%s.' % dns_domain


# TODO(asarfaty) use dns-domain/nameserver from network az instead of global
class DNSExtensionDriver(driver_api.ExtensionDriver):
    _supported_extension_alias = dns.ALIAS

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, plugin_context, request_data, db_data):
        dns_domain = request_data.get(dns.DNSDOMAIN)
        if not validators.is_attr_set(dns_domain):
            return

        if dns_domain:
            obj_reg.new_instance('NetworkDNSDomain', plugin_context,
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
            net_dns_domain = obj_reg.load_class('NetworkDNSDomain').get_object(
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
            obj_reg.new_instance('NetworkDNSDomain', plugin_context,
                                 network_id=net_id,
                                 dns_domain=new_value).create()
            db_data[dns.DNSDOMAIN] = new_value

    def process_create_port(self, plugin_context, request_data, db_data):
        if not (request_data.get(dns.DNSNAME) or
                request_data.get(dns.DNSDOMAIN)):
            return
        dns_name, is_dns_domain_default = self._get_request_dns_name(
            request_data, db_data['network_id'], plugin_context)
        if is_dns_domain_default:
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        self._create_port_dns_record(plugin_context, request_data, db_data,
                                     network, dns_name)

    def _create_port_dns_record(self, plugin_context, request_data, db_data,
                                network, dns_name):
        external_dns_domain = (request_data.get(dns.DNSDOMAIN) or
                               network.get(dns.DNSDOMAIN))
        current_dns_name, current_dns_domain = (
            self._calculate_current_dns_name_and_domain(
                dns_name, external_dns_domain,
                self.external_dns_not_needed(plugin_context, network)))

        dns_data_obj = obj_reg.new_instance(
            'PortDNS',
            plugin_context,
            port_id=db_data['id'],
            current_dns_name=current_dns_name,
            current_dns_domain=current_dns_domain,
            previous_dns_name='',
            previous_dns_domain='',
            dns_name=dns_name,
            dns_domain=request_data.get(dns.DNSDOMAIN, ''))
        dns_data_obj.create()
        return dns_data_obj

    def _calculate_current_dns_name_and_domain(self, dns_name,
                                               external_dns_domain,
                                               no_external_dns_service):
        # When creating a new PortDNS object, the current_dns_name and
        # current_dns_domain fields hold the data that the integration driver
        # will send to the external DNS service. They are set to non-blank
        # values only if all the following conditions are met:
        # 1) There is an external DNS integration driver configured
        # 2) The user request contains a valid non-blank value for the port's
        #    dns_name
        # 3) The user request contains a valid non-blank value for the port's
        #    dns_domain or the port's network has a non-blank value in its
        #    dns_domain attribute
        are_both_dns_attributes_set = dns_name and external_dns_domain
        if no_external_dns_service or not are_both_dns_attributes_set:
            return '', ''
        return dns_name, external_dns_domain

    def _update_dns_db(self, dns_name, dns_domain, db_data,
                      plugin_context, has_fixed_ips):
        dns_data_db = obj_reg.load_class('PortDNS').get_object(
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
            dns_data_db = obj_reg.new_instance(
                'PortDNS', plugin_context, port_id=db_data['id'],
                current_dns_name=dns_name, current_dns_domain=dns_domain,
                previous_dns_name='', previous_dns_domain='',
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
        dns_data_db = obj_reg.load_class('PortDNS').get_object(
            plugin_context,
            port_id=db_data['id'])
        if dns_data_db:
            dns_data_db['dns_name'] = dns_name
            dns_data_db.update()
            return dns_data_db
        if dns_name:
            dns_data_db = obj_reg.new_instance(
                'PortDNS', plugin_context, port_id=db_data['id'],
                current_dns_name='', current_dns_domain='',
                previous_dns_name='', previous_dns_domain='',
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
        return _dotted_domain(cfg.CONF.dns_domain)

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

        provider_type = network.get('provider:network_type')
        if not provider_type:
            return True

        if network['router:external']:
            return True
        return False


class DNSExtensionDriverNSXv3(DNSExtensionDriver):

    def initialize(self):
        self._availability_zones = nsx_az.NsxV3AvailabilityZones()
        LOG.info("DNSExtensionDriverNSXv3 initialization complete")
        self.config_dns_domain = cfg.CONF.nsx_v3.dns_domain

    def _get_network_and_az(self, network_id, context):
        if not context:
            context = n_context.get_admin_context()
        network = self._get_network(context, network_id)
        if az_def.AZ_HINTS in network and network[az_def.AZ_HINTS]:
            az_name = network[az_def.AZ_HINTS][0]
            az = self._availability_zones.get_availability_zone(az_name)
            return network, az
        az = self._availability_zones.get_default_availability_zone()
        return network, az

    def _get_dns_domain(self, network_id, context=None):
        # first try to get the dns_domain configured on the network
        net, az = self._get_network_and_az(network_id, context)
        if net.get('dns_domain'):
            return _dotted_domain(net['dns_domain'])
        # try to get the dns-domain from the specific availability zone
        # of this network
        if (az.dns_domain and
            _dotted_domain(az.dns_domain) !=
            _dotted_domain(DNS_DOMAIN_DEFAULT)):
            dns_domain = az.dns_domain
        # Global nsx_v3 dns domain
        elif (self.config_dns_domain and
              (_dotted_domain(self.config_dns_domain) !=
               _dotted_domain(DNS_DOMAIN_DEFAULT))):
            dns_domain = self.config_dns_domain
        # Global neutron dns domain
        elif cfg.CONF.dns_domain:
            dns_domain = cfg.CONF.dns_domain
        else:
            return ''
        return _dotted_domain(dns_domain)

    def external_dns_not_needed(self, context, network):
        dns_driver = _get_dns_driver()
        if not dns_driver:
            return True
        provider_type = network.get('provider:network_type')
        if not provider_type:
            return True

        if network['router:external']:
            return True
        return False


class DNSExtensionDriverNSXp(DNSExtensionDriverNSXv3):

    def initialize(self):
        self._availability_zones = nsxp_az.NsxPAvailabilityZones()
        LOG.info("DNSExtensionDriverNSXp initialization complete")
        self.config_dns_domain = cfg.CONF.nsx_p.dns_domain


class DNSExtensionDriverDVS(DNSExtensionDriver):

    def initialize(self):
        LOG.info("DNSExtensionDriverDVS initialization complete")

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


def _send_data_to_external_dns_service(context, dns_driver, dns_domain,
                                       dns_name, records):
    try:
        dns_driver.create_record_set(context, dns_domain, dns_name, records)
    except (dns_exc.DNSDomainNotFound, dns_exc.DuplicateRecordSet) as e:
        LOG.exception("Error publishing port data in external DNS "
                      "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                      "DNS service driver message '%(message)s'",
                      {"name": dns_name,
                       "domain": dns_domain,
                       "message": e.msg})


def _remove_data_from_external_dns_service(context, dns_driver, dns_domain,
                                           dns_name, records):
    try:
        dns_driver.delete_record_set(context, dns_domain, dns_name, records)
    except (dns_exc.DNSDomainNotFound, dns_exc.DuplicateRecordSet) as e:
        LOG.exception("Error deleting port data from external DNS "
                      "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                      "IP addresses '%(ips)s'. DNS service driver message "
                      "'%(message)s'",
                      {"name": dns_name,
                       "domain": dns_domain,
                       "message": e.msg,
                       "ips": ', '.join(records)})


def _create_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    port = kwargs['port']
    dns_data_db = obj_reg.load_class('PortDNS').get_object(
        context, port_id=port['id'])
    if not (dns_data_db and dns_data_db['current_dns_name']):
        return
    records = [ip['ip_address'] for ip in port['fixed_ips']]
    _send_data_to_external_dns_service(context, dns_driver,
                                       dns_data_db['current_dns_domain'],
                                       dns_data_db['current_dns_name'],
                                       records)


def _update_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    updated_port = kwargs['port']
    original_port = kwargs.get('original_port')
    if not original_port:
        return
    original_ips = [ip['ip_address'] for ip in original_port['fixed_ips']]
    updated_ips = [ip['ip_address'] for ip in updated_port['fixed_ips']]
    is_dns_name_changed = (updated_port[dns.DNSNAME] !=
                           original_port[dns.DNSNAME])
    is_dns_domain_changed = (dns.DNSDOMAIN in updated_port and
                             updated_port[dns.DNSDOMAIN] !=
                             original_port[dns.DNSDOMAIN])
    ips_changed = set(original_ips) != set(updated_ips)
    if not any((is_dns_name_changed, is_dns_domain_changed, ips_changed)):
        return
    dns_data_db = obj_reg.load_class('PortDNS').get_object(
        context, port_id=updated_port['id'])
    if not (dns_data_db and
            (dns_data_db['previous_dns_name'] or
             dns_data_db['current_dns_name'])):
        return
    if dns_data_db['previous_dns_name']:
        _remove_data_from_external_dns_service(
            context, dns_driver, dns_data_db['previous_dns_domain'],
            dns_data_db['previous_dns_name'], original_ips)
    if dns_data_db['current_dns_name']:
        _send_data_to_external_dns_service(context, dns_driver,
                                           dns_data_db['current_dns_domain'],
                                           dns_data_db['current_dns_name'],
                                           updated_ips)


def _delete_port_in_external_dns_service(resource, event,
                                         trigger, payload=None):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = payload.context
    port_id = payload.resource_id
    dns_data_db = obj_reg.load_class('PortDNS').get_object(
        context, port_id=port_id)
    if not dns_data_db:
        return
    if dns_data_db['current_dns_name']:
        ip_allocations = obj_reg.load_class('IPAllocation').get_objects(
            context, port_id=port_id)
        records = [str(alloc['ip_address']) for alloc in ip_allocations]
        _remove_data_from_external_dns_service(
            context, dns_driver, dns_data_db['current_dns_domain'],
            dns_data_db['current_dns_name'], records)


registry.subscribe(
    _create_port_in_external_dns_service, resources.PORT, events.AFTER_CREATE)
registry.subscribe(
    _update_port_in_external_dns_service, resources.PORT, events.AFTER_UPDATE)
registry.subscribe(
    _delete_port_in_external_dns_service, resources.PORT, events.BEFORE_DELETE)
