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

import base64

from oslo_log import log as logging
from oslo_serialization import jsonutils
import re
import requests

from tempest import config

import vmware_nsx_tempest.services.utils as utils

requests.packages.urllib3.disable_warnings()
CONF = config.CONF
LOG = logging.getLogger(__name__)


class VSMClient(object):
    """NSX-v client.

    The client provides the API operations on its components.
    The purpose of this rest client is to query backend components after
    issuing corresponding API calls from OpenStack. This is to make sure
    the API calls has been realized on the NSX-v backend.
    """
    API_VERSION = "2.0"

    def __init__(self, host, username, password, *args, **kwargs):
        self.force = True if 'force' in kwargs else False
        self.host = host
        self.username = username
        self.password = password
        self.version = None
        self.endpoint = None
        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.headers = None
        self.api_version = VSMClient.API_VERSION
        self.default_scope_id = None

        self.__set_headers()
        self._version = self.get_vsm_version()

    def __set_endpoint(self, endpoint):
        self.endpoint = endpoint

    def get_endpoint(self):
        return self.endpoint

    def __set_content_type(self, content_type):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type

    def __set_accept_type(self, accept_type):
        self.accept_type = accept_type

    def get_accept_type(self):
        return self.accept_type

    def __set_api_version(self, api_version):
        self.api_version = api_version

    def get_api_version(self):
        return self.api_version

    def __set_url(self, version=None, secure=None, host=None, endpoint=None):
        version = self.api_version if version is None else version
        secure = self.secure if secure is None else secure
        host = self.host if host is None else host
        endpoint = self.endpoint if endpoint is None else endpoint
        http_type = 'https' if secure else 'http'
        self.url = '%s://%s/api/%s%s' % (http_type, host, version, endpoint)

    def get_url(self):
        return self.url

    def __set_headers(self, content=None, accept=None):
        content_type = self.content_type if content is None else content
        accept_type = self.accept_type if accept is None else accept
        auth_cred = self.username + ":" + self.password
        auth = base64.b64encode(auth_cred)
        headers = {}
        headers['Authorization'] = "Basic %s" % auth
        headers['Content-Type'] = content_type
        headers['Accept'] = accept_type
        self.headers = headers

    def get(self, endpoint=None, params=None):
        """Basic query GET method for json API request."""
        self.__set_url(endpoint=endpoint)
        response = requests.get(self.url, headers=self.headers,
                                verify=self.verify, params=params)
        return response

    def delete(self, endpoint=None, params=None):
        """Basic delete API method on endpoint."""
        self.__set_url(endpoint=endpoint)
        response = requests.delete(self.url, headers=self.headers,
                                   verify=self.verify, params=params)
        return response

    def post(self, endpoint=None, body=None):
        """Basic post API method on endpoint."""
        self.__set_url(endpoint=endpoint)
        response = requests.post(self.url, headers=self.headers,
                                 verify=self.verify,
                                 data=jsonutils.dumps(body))
        return response

    def get_all_vdn_scopes(self):
        """Retrieve existing network scopes"""
        self.__set_api_version('2.0')
        self.__set_endpoint("/vdn/scopes")
        response = self.get()
        return response.json()['allScopes']

    # return the vdn_scope_id for the priamry Transport Zone
    def get_vdn_scope_id(self):
        """Retrieve existing network scope id."""
        scopes = self.get_all_vdn_scopes()
        if len(scopes) == 0:
            return scopes[0]['objectId']
        return CONF.nsxv.vdn_scope_id

    def get_vdn_scope_by_id(self, scope_id):
        """Retrieve existing network scopes id"""
        self.__set_api_version('2.0')
        self.__set_endpoint("/vdn/scopes/%s" % scope_id)
        return self.get().json()

    def get_vdn_scope_by_name(self, name):
        """Retrieve network scope id of existing scope name:

        nsxv_client.get_vdn_scope_id_by_name('TZ1')
        """
        scopes = self.get_all_vdn_scopes()
        if name is None:
            for scope in scopes:
                if scope['objectId'] == CONF.nsxv.vdn_scope_id:
                    return scope
        else:
            for scope in scopes:
                if scope['name'] == name:
                    return scope
        return None

    def get_all_logical_switches(self, vdn_scope_id=None):
        lswitches = []
        self.__set_api_version('2.0')
        vdn_scope_id = vdn_scope_id or self.get_vdn_scope_id()
        endpoint = "/vdn/scopes/%s/virtualwires" % (vdn_scope_id)
        self.__set_endpoint(endpoint)
        response = self.get()
        paging_info = response.json()['dataPage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        msg = ("There are total %s logical switches and page size is %s"
               % (total_count, page_size))
        LOG.debug(msg)
        pages = utils.ceil(total_count, page_size)
        LOG.debug("Total pages: %s" % pages)
        for i in range(pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            lswitches += response.json()['dataPage']['data']
        return lswitches

    def get_logical_switch(self, name):
        """Get the logical switch based on the name.

        The uuid of the OpenStack L2 network. Return ls if found,
        otherwise return None.
        """
        lswitches = self.get_all_logical_switches()
        lswitch = [ls for ls in lswitches if ls['name'] == name]
        if len(lswitch) == 0:
            LOG.debug('logical switch %s NOT found!' % name)
            lswitch = None
        else:
            ls = lswitch[0]
            LOG.debug('Found lswitch: %s' % ls)
        return ls

    def delete_logical_switch(self, name):
        """Delete logical switch based on name.

        The name of the logical switch on NSX-v is the uuid
        of the openstack l2 network.
        """
        ls = self.get_logical_switch(name)
        if ls is not None:
            endpoint = '/vdn/virtualwires/%s' % ls['objectId']
            response = self.delete(endpoint=endpoint)
            if response.status_code == 200:
                LOG.debug('Successfully deleted logical switch %s' % name)
            else:
                LOG.debug('ERROR @delete ls=%s failed with response code %s' %
                          (name, response.status_code))

    def get_all_edges(self):
        """Get all edges on NSX-v backend."""
        self.__set_api_version('4.0')
        self.__set_endpoint('/edges')
        edges = []
        response = self.get()
        paging_info = response.json()['edgePage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        msg = "There are total %s edges and page size is %s" % (total_count,
                                                                page_size)
        LOG.debug(msg)
        pages = utils.ceil(total_count, page_size)
        for i in range(pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            edges += response.json()['edgePage']['data']
        return edges

    def get_edge(self, name):
        """Get edge based on the name, which is OpenStack router.

        Return edge if found, else return None.
        """
        edges = self.get_all_edges()
        edge = [e for e in edges if e['name'] == name]
        if len(edge) == 0:
            LOG.debug('Edge %s NOT found!' % name)
            edge = None
        else:
            edge = edge[0]
            LOG.debug('Found edge: %s' % edge)
        return edge

    def get_dhcp_edge_config(self, edge_id):
        """Get dhcp edge config.

        Return edge information.
        """
        self.__set_api_version('4.0')
        self.__set_endpoint('/edges/%s/dhcp/config' % edge_id)
        response = self.get()
        return response

    def get_excluded_vm_name_list(self):
        """Get excluded vm's list info from beckend.

        After disabling port security of vm port, vm will get added
        in exclude list.This method returns the list of vm's present
        in exclude list.
        Returns exclude list of vm's name.
        """
        self.__set_api_version('2.1')
        self.__set_endpoint('/app/excludelist')
        response = self.get()
        response_list = []
        exclude_list = []
        response_list = response.json()[
            'excludeListConfigurationDto']['excludeMembers']
        exclude_list = [member['member']['name'] for member in response_list
                        if member['member']['name']]
        return exclude_list

    def get_dhcp_edge_info(self):
        """Get dhcp edge info.

        Return edge if found, else return None.
        """
        edges = self.get_all_edges()
        edge_list = []
        for e in edges:
            if (not e['edgeStatus'] == 'GREY'
                    and not e['state'] == 'undeployed'):
                p = re.compile(r'dhcp*')
                if (p.match(e['name'])):
                    edge_list.append(e['recentJobInfo']['edgeId'])
        count = 0
        result_edge = {}
        for edge_id in edge_list:
            response = self.get_dhcp_edge_config(edge_id)
            paging_info = response.json()
            if (paging_info['staticBindings']['staticBindings']):
                result_edge[count] = paging_info
                count += 1
            else:
                LOG.debug('Host Routes are not avilable for %s ' % edge_id)
        if (count > 0):
            edge = result_edge[0]
        else:
            edge = None
        return edge

    def get_vsm_version(self):
        """Get the VSM client version including major, minor, patch, & build#.

        Build number, e.g. 6.2.0.2986609
        return: vsm version
        """
        self.__set_api_version('1.0')
        self.__set_endpoint('/appliance-management/global/info')
        response = self.get()
        json_ver = response.json()['versionInfo']
        return '.'.join([json_ver['majorVersion'], json_ver['minorVersion'],
                         json_ver['patchVersion'], json_ver['buildNumber']])
