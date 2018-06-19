# Copyright 2017 VMware, Inc.
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

import getopt
import logging
import re
import sys
import xml.etree.ElementTree as et

from keystoneauth1 import identity
from keystoneauth1 import session
import libvirt
from neutronclient.v2_0 import client
import nova.conf

CONF = nova.conf.CONF
logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def usage():
    print("python nsx_instance_if_migrate.py --username=<username> "
          "--password=<password> --project=<project> "
          "--auth-url=<keystone auth URL> "
          "[--project-domain-id=<project domain>] "
          "[--user-domain-id=<user domain>] "
          "[--machine-type=<migrated machine type] "
          "[--logfile=<log file>] "
          "[--nsx-bridge=<NSX managed vSwitch>]\n\n"
          "Convert libvirt interface definitions on a KVM host, to NSX "
          "managed vSwitch definitions\n\n"
          "  username: Admin user's username\n"
          "  password: Admin user's password\n"
          "  keystone auth URL: URL to keystone's authentication service\n"
          "  project domain: Keystone project domain\n"
          "  user domain: Keystone user domain\n"
          "  migrated machine type: Overwrites libvirt's machine type\n"
          "  log file: Output log of the command execution\n"
          "  NSX managed vSwitch: vSwitch on host, managed by NSX\n\n")

    sys.exit()


def get_opts():
    opts = {}
    o = []
    p = re.compile('^-+')
    try:
        o, a = getopt.getopt(sys.argv[1:], 'h', ['help',
                                                 'username=',
                                                 'password=',
                                                 'project=',
                                                 'project-domain-id=',
                                                 'user-domain-id=',
                                                 'auth-url=',
                                                 'machine-type=',
                                                 'logfile=',
                                                 'nsx-bridge='])
    except getopt.GetoptError as err:
        LOG.error(err)
        usage()
    for opt, val in o:
        if opt in ('h', 'help'):
            usage()
        else:
            opts[p.sub('', opt)] = val

    for mandatory_key in ['username', 'password', 'project', 'auth-url']:
        if opts.get(mandatory_key) is None:
            LOG.error("%s must be specified!", mandatory_key)
            usage()

    return opts


def xmltag_text_get(obj, tag_name):
    tag_obj = obj.find(tag_name)
    if tag_obj is not None:
        return tag_obj.text


def xmltag_attr_get(obj, tag, attr):
    tag_obj = obj.find(tag)
    if tag_obj is not None:
        return tag_obj.get(attr)


def xmltag_set(elem, tag, **kwargs):
    sub_elem = elem.find(tag)
    if sub_elem is None:
        sub_elem = et.SubElement(elem, tag)
    for attr in kwargs.keys():
        sub_elem.set(attr, kwargs.get(attr))
    return sub_elem


def iface_migrate(neutron, instance_name, iface, nsx_switch):
    iface.set('type', 'bridge')
    xmltag_set(iface, 'source', bridge=nsx_switch)
    virt_port = xmltag_set(iface, 'virtualport', type='openvswitch')
    instance_mac = xmltag_attr_get(iface, 'mac', 'address')
    if instance_mac is None:
        LOG.error("Couldn't find MAC address for instance %s", instance_name)
        return

    ports = neutron.list_ports(fields=['id'], mac_address=instance_mac)
    if len(ports['ports']) != 1:
        LOG.error('For instance %(vm)s, invalid ports received from neutron: '
                  '%(ports)s', {'vm': instance_name, 'ports': ports})
        return

    neutron_port_id = ports['ports'][0]['id']
    xmltag_set(virt_port, 'parameters', interfaceid=neutron_port_id)
    xmltag_set(iface, 'driver', name='qemu')

    tap_dev = xmltag_attr_get(iface, 'target', 'dev')
    if tap_dev is None:
        LOG.error("For instance %(vm)s, couldn't find tap device for "
                  "interface", instance_name)

    # remove script tag if found
    script_tag = iface.find('script')
    if script_tag is not None:
        iface.remove(script_tag)


def is_valid_os_data(libvirt_conn, os_type, os_arch, os_machine):
    caps_xml = libvirt_conn.getCapabilities()
    caps_root = et.fromstring(caps_xml)
    for guest_tag in caps_root.findall('guest'):
        if (xmltag_text_get(guest_tag, 'os_type') == os_type and
            xmltag_attr_get(guest_tag, 'arch', 'name') == os_arch):
            for machine_tag in guest_tag.find('arch').findall('machine'):
                if machine_tag.text == os_machine:
                    return True
    return False


def instance_migrate(libvirt_conn, neutron, instance, machine_type,
                     nsx_switch):
    xml = instance.XMLDesc()
    root = et.fromstring(xml)

    instance_name = xmltag_text_get(root, 'name')
    if instance_name is None:
        LOG.error("Couldn't find instance name in XML")
        return

    instance_uuid = xmltag_text_get(root, 'uuid')
    if instance_uuid is None:
        LOG.error("Couldn't find UUID for instance %s", instance_name)
        return

    # Validate that os is supported by hypervisor
    os_tag = root.find('os')
    if os_tag is None:
        LOG.error("Couldn't find OS tag for instance %s", instance_name)
        return
    type_tag = os_tag.find('type')
    if not is_valid_os_data(libvirt_conn, type_tag.text, type_tag.get('arch'),
                            type_tag.get('machine')):
        LOG.error("Instance %s OS data is invalid or not supported by "
                  "hypervisor", instance_name)
        return

    if machine_type is not None:
        type_tag.set('machine', machine_type)

    devs = root.find('devices')
    ifaces = devs.findall('interface')

    if not ifaces:
        LOG.error('No interfaces to migrate for instance %s', instance_name)

    for iface in ifaces:
        iface_migrate(neutron, instance_name, iface, nsx_switch)

    instance.undefine()
    libvirt_conn.defineXML(et.tostring(root))
    LOG.info('Migrated instance %(vm)s (%(uuid)s) successfully!',
             {'vm': instance_name, 'uuid': instance_uuid})


def main():
    opts = get_opts()
    if opts.get('logfile'):
        f_handler = logging.FileHandler(opts.get('logfile'))
        f_formatter = logging.Formatter(
            '%(asctime)s %(levelname)s %(message)s')
        f_handler.setFormatter(f_formatter)
        LOG.addHandler(f_handler)

    conn = libvirt.open('qemu:///system')
    if conn is None:
        LOG.error('Failed to connect to libvirt')
        exit(1)

    auth = identity.Password(username=opts['username'],
                             password=opts['password'],
                             project_name=opts['project'],
                             project_domain_id=opts.get('project-domain-id',
                                                        'default'),
                             user_domain_id=opts.get('user-domain-id',
                                                     'default'),
                             auth_url=opts['auth-url'])

    if auth is None:
        LOG.error('Failed to authenticate with keystone')
        exit(1)

    sess = session.Session(auth=auth)
    if sess is None:
        LOG.error('Failed to create keystone session')
        exit(1)

    neutron = client.Client(session=sess)
    if neutron is None:
        LOG.error('Failed to create neutron session')
        exit(1)

    instances = conn.listAllDomains()
    if not instances:
        LOG.error('No instances to migrate')

    for instance in instances:
        try:
            instance_migrate(conn, neutron, instance, opts.get('machine-type'),
                             opts.get('nsx-bridge', CONF.neutron.ovs_bridge))
        except Exception as e:
            LOG.error('Failed to migrate instance with exception %s', e)


if __name__ == "__main__":
    main()
