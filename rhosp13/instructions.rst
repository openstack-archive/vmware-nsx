==================================================
Setting up RHOSP13 director for NSX-T integration
==================================================

This guide provides instruction for updating the following components
on RHOSP director:

- openstack-puppet
- openstack-tripleo-heat-templates

The tarballs nsx-rhosp-openstack-puppet.tar.gz and
nsx-rhosp-openstack-tripleo-heat-templates.tar.gz contain updated versions
for these components.

The following instructions provide detailed information regarding upgrading
software on the RHOSP director using these tarballs:

1. Download tarball in RHOSP director’s home directory
2. Verify if an upgrade is needed:
$ test -e /usr/share/openstack-heat-tripleo-templates/docker/services/neutron-plugin-nsx.yaml && echo “OK” || echo “PATCH ME”

3. Copy both tarballs in /usr/share/openstack
$ sudo cp ~/nsx-rhosp-*.tar.gz /usr/share/openstack

4.	Expand the archives
# cd /usr/share/openstack
# tar xzf nsx-rhosp-*.tar.gz

