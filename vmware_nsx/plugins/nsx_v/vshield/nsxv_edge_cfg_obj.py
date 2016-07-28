# Copyright 2014 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

import abc

from oslo_serialization import jsonutils
import six

from vmware_nsx.plugins.nsx_v.vshield import vcns


@six.add_metaclass(abc.ABCMeta)
class NsxvEdgeCfgObj(object):

    def __init__(self):
        return

    @abc.abstractmethod
    def get_service_name(self):
        return

    @abc.abstractmethod
    def serializable_payload(self):
        return

    @staticmethod
    def get_object(vcns_obj, edge_id, service_name):
        uri = "%s/%s/%s" % (vcns.URI_PREFIX,
                            edge_id,
                            service_name)

        h, v = vcns_obj.do_request(
            vcns.HTTP_GET,
            uri,
            decode=True)

        return v

    def submit_to_backend(self, vcns_obj, edge_id):
        uri = "%s/%s/%s/config" % (vcns.URI_PREFIX,
                                   edge_id,
                                   self.get_service_name())

        payload = jsonutils.dumps(self.serializable_payload(), sort_keys=True)

        if payload:
            return vcns_obj.do_request(
                vcns.HTTP_PUT,
                uri,
                payload,
                format='json',
                encode=False)
