Welcome!
========
vmware_nsx_tempest is a plugin module to openstack tempest project.

If you are not familiar with tempest, please refer to::

   http://docs.openstack.org/developer/tempest

It is implemented with tempest external plugin.
The official design sepcification is at::

    https://review.openstack.org/#/c/184992/

Overview
========

vmware_nsx_tempest hosts vmware_nsx's functional api and scenario tests.

All vmware_nsx_tempest tests are in "master" branch. For this reason,
it is recommended to have your own developer version of vmware-nsx repo
installed outside the devstack folder, /opt/stack/.

For example at /opt/devtest folder. In doing so, you can install
editable vmware-nsx repo under tempest VENV environemnt.

Installation:
-------------

#. On your own development folder, for example /opt/devtest/,
   install your own tempest development env at /opt/devtest/os-tempest/::

    $ cd /opt/devtest
    $ git clone https://github.com/openstack/tempest os-tempest

#. Install virtualenv with the following command::

    $ cd /opt/devtest/os-tempest
    $ ./run_tempest.sh -u not_exist_tests

#. Install vmware-nsx master branch at /opt/devtest/vmware-nsx::

    $ cd /opt/devtest
    $ git clone https://github.com/openstack/vmware-nsx

#. Install vmware_nsx_tempest in your tempest development environment::

    $ cd /opt/devtest/os-tempest
    $ source .venv/bin/activate
    $ pip install -e /opt/devtest/vmware-nsx/

   Run command::

    $ pip show vmware-nsx

   You should observe the following statements::

    Location: /opt/devtest/vmware-nsx

   and under section of Entry-points::

    [tempest.test_plugins]
    vmware-nsx-tempest-plugin = vmware_nsx_tempest.plugin:VMwareNsxTempestPlugin

#. Validate installed vmware_nsx_tempest succesfully do::

    $ cd /opt/devtest/os-tempest
    $ tools/with_venv.sh testr list-tests vmware_nsx_tempest.*l2_gateway

Your installation failed, if no tests are shown.

Execution:
----------

vmware_nsx_tempest tests are tempest tests, you need to
run from tempest directory. For example, to run only l2-gateway tests::

    $ cd /opt/devtest/os-tempest
    $ ./run_tempest.sh -t vmware_nsx_tempest.*test_l2_gateway
    $ ./run_tempest.sh -d vmware_nsx_tempest.tests.nsxv.api.test_l2_gateway_connection.L2GatewayConnectionTest.test_csuld_single_device_interface_vlan

TechNote on vmware_nsx_tempest:
-------------------------------

vmware_nsx_tempest is a plugin to tempest, not neutron, nor vmware_nsx.

It is defined by tempest.test_plugins.

Modules within vmware_nsx_tempest can not see resources defined
by vmware_nsx. Commands like following are not acceptable, unless
vmware_nsx is installed in your tempest environment::

    from vmware_nsx._i18n import _LE
    import vmware_nsx.shell.admin.plugins.common.utils as admin_utils

TechNote on logging:
--------------------
tempest repo itself does not enforce LOG complying to _i18n.
So for tempest tests for vmware-nsx, that is vmware_nsx_tempest,
use LOG.debug() command.

However, if you need to log other than debug level, please do::

    from vmware_nsx_tempest._i18n import _LI
    from vmware_nsx_tempest._i18n import _LE
    from vmware_nsx_tempest._i18n import _LW

Customize it depending on the log level your scripts will use.
