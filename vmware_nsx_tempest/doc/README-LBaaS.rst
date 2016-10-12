Overview
========

This document describes what LBaaS tests are not supported at different
NSX plugin's and backends.

NOTE::

    All LBaaS API & Scenario tests should PASS with exceptions
    due to NSX plugins and features supported by backend.

    For how tests can be skipped for specific plugin and backend,
    please refer to paragraph "Config for Test Execution".

NOTE::

    We no longer support LBaaS v1. So this document and LBaaS tests
    only applys to releases from Mitaka/Marvin or later.

Limitation:
-----------

NSX-v with VMware LBaaS driver::

    #. LBaaS networks need to attach to exclusive router
    #. One tenant per subnet
    #. L7 switching not supported

NSX-v3 with Octavia driver::

    #. upstream implemenation - all tests should PASS.
    #. scenario tests take long time, it might fail with fixture timeout.

Config for Test execution:
--------------------------

Following configuration attributes used to controll test execution::

    #. no_router_type at group/session nsxv

       Default is False, and is used to run LBaaS tests in NSX-v environment.
       To run in NSX-t environment, set it to True

    #. bugs_to_resolve at group/session nsxv

       For test to skip if bug-ID presented in this attribute.
       The test will use testtools.skipIf(condition, reason) to skip if its ID in the bugs_to_resolve list.

local.conf:
----------
NSX-v::
    [nsxv]
    no_router_type=False
    bugs_to_resolve=1641902,1715126,1703396,1739510

NSX-v3::
    [compute]
    build_timeout=900
    build_interval=2

    [nsxv]
    no_router_type=True

Execution:
----------

#. Use testr list-tests command to generate test suite for run API and Scenario tests::

    tools/with_venv.sh testr list-tests nsxv.api.lbaas
    tools/with_venv.sh testr list-tests nsxv.scenarion.test_lbaas

#. l7 switching tests take long time to complete. If got fixture timeout, do::

    OS_TEST_TIMEOUT=2400 ./run_tempest.sh -t test_lbaas_l7_switching_ops
