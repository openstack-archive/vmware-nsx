# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg


def override_nsx_ini_test():
    cfg.CONF.set_override("default_tz_uuid", "fake_tz_uuid")
    cfg.CONF.set_override("nsx_controllers", ["fake1", "fake_2"])
    cfg.CONF.set_override("nsx_user", "foo")
    cfg.CONF.set_override("nsx_password", "bar")
    cfg.CONF.set_override("default_l3_gw_service_uuid", "whatever")
    cfg.CONF.set_override("default_l2_gw_service_uuid", "whatever")
    cfg.CONF.set_override("manager_uri", "https://fake_manager",
                          group="nsxv")
    cfg.CONF.set_override("user", "fake_user", group="nsxv")
    cfg.CONF.set_override("password", "fake_password", group="nsxv")
    cfg.CONF.set_override("vdn_scope_id", "fake_vdn_scope_id",
                          group="nsxv")
    cfg.CONF.set_override("dvs_id", "fake_dvs_id", group="nsxv")


def override_nsx_ini_full_test():
    cfg.CONF.set_override("default_tz_uuid", "fake_tz_uuid")
    cfg.CONF.set_override("nsx_controllers", ["fake1", "fake_2"])
    cfg.CONF.set_override("nsx_user", "foo")
    cfg.CONF.set_override("nsx_password", "bar")
    cfg.CONF.set_override("default_l3_gw_service_uuid", "whatever")
    cfg.CONF.set_override("default_l2_gw_service_uuid", "whatever")
    cfg.CONF.set_override("nsx_default_interface_name", "whatever")
    cfg.CONF.set_override("http_timeout", 13)
    cfg.CONF.set_override("redirects", 12)
    cfg.CONF.set_override("retries", "11")
