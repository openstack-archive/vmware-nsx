# Copyright 2015 VMware, Inc.
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
#
import abc
import contextlib
import copy
import datetime
import eventlet
import itertools
import logging
import requests
import six
import six.moves.urllib.parse as urlparse

from eventlet import greenpool
from eventlet import pools
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from oslo_config import cfg
from oslo_log import log
from oslo_service import loopingcall
from requests import adapters
from requests import exceptions as requests_exceptions
from vmware_nsx._i18n import _, _LI, _LW
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import exceptions


LOG = log.getLogger(__name__)

# disable warning message for each HTTP retry
logging.getLogger(
    "requests.packages.urllib3.connectionpool").setLevel(logging.ERROR)


@six.add_metaclass(abc.ABCMeta)
class AbstractHTTPProvider(object):
    """Interface for providers of HTTP connections which
    are responsible for creating and validating connections
    for their underlying HTTP support.
    """

    @property
    def default_scheme(self):
        return 'https'

    @abc.abstractproperty
    def provider_id(self):
        """A unique string name for this provider."""
        pass

    @abc.abstractmethod
    def validate_connection(self, cluster_api, endpoint, conn):
        """Validate the said connection for the given endpoint and cluster.
        """
        pass

    @abc.abstractmethod
    def new_connection(self, cluster_api, provider):
        """Create a new http connection for the said cluster and
        cluster provider. The actual connection should duck type
        requests.Session http methods (get(), put(), etc.).
        """
        pass

    @abc.abstractmethod
    def is_connection_exception(self, exception):
        """Determine if the given exception is related to connection
        failure. Return True if it's a connection exception and
        False otherwise.
        """


class TimeoutSession(requests.Session):
    """Extends requests.Session to support timeout
    at the session level.
    """

    def __init__(self, timeout=None, read_timeout=None):
        self.timeout = timeout or cfg.CONF.nsx_v3.http_timeout
        self.read_timeout = read_timeout or cfg.CONF.nsx_v3.http_read_timeout
        super(TimeoutSession, self).__init__()

    # wrapper timeouts at the session level
    # see: https://goo.gl/xNk7aM
    def request(self, *args, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.timeout, self.read_timeout)
        return super(TimeoutSession, self).request(*args, **kwargs)


class NSXRequestsHTTPProvider(AbstractHTTPProvider):
    """Concrete implementation of AbstractHTTPProvider
    using requests.Session() as the underlying connection.
    """

    @property
    def provider_id(self):
        return "%s-%s" % (requests.__title__, requests.__version__)

    def validate_connection(self, cluster_api, endpoint, conn):
        client = nsx_client.NSX3Client(conn, url_prefix=endpoint.provider.url)
        zones = client.get('transport-zones')
        if not zones or zones['result_count'] <= 0:
            msg = _("No transport zones found "
                    "for '%s'") % endpoint.provider.url
            LOG.warning(msg)
            raise exceptions.ResourceNotFound(
                manager=endpoint.provider.url, operation=msg)

    def new_connection(self, cluster_api, provider):
        session = TimeoutSession(cluster_api.http_timeout,
                                 cluster_api.http_read_timeout)
        session.auth = (cluster_api.username, cluster_api.password)
        # NSX v3 doesn't use redirects
        session.max_redirects = 0

        session.verify = not cluster_api.insecure
        if session.verify and cluster_api.ca_file:
            # verify using the said ca bundle path
            session.verify = cluster_api.ca_file

        # we are pooling with eventlet in the cluster class
        adapter = adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1,
            max_retries=cluster_api.retries,
            pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session

    def is_connection_exception(self, exception):
        return isinstance(exception, requests_exceptions.ConnectionError)


class ClusterHealth(object):
    """Indicator of overall cluster health with respect
    to the connectivity of the clusters managed endpoints.
    """
    # all endpoints are UP
    GREEN = 'GREEN'
    # at least 1 endpoint is UP, but 1 or more are DOWN
    ORANGE = 'ORANGE'
    # all endpoints are DOWN
    RED = 'RED'


class EndpointState(object):
    """Tracks the connectivity state for a said endpoint.
    """
    # no UP or DOWN state recorded yet
    INITIALIZED = 'INITIALIZED'
    # endpoint has been validate and is good
    UP = 'UP'
    # endpoint can't be reached or validated
    DOWN = 'DOWN'


class Provider(object):
    """Data holder for a provider which has a unique id
    and a connection URL.
    """

    def __init__(self, provider_id, provider_url):
        self.id = provider_id
        self.url = provider_url

    def __str__(self):
        return str(self.url)


class Endpoint(object):
    """A single NSX manager endpoint (host) which includes
    related information such as the endpoint's provider,
    state, etc.. A pool is used to hold connections to the
    endpoint which are doled out when proxying HTTP methods
    to the underlying connections.
    """

    def __init__(self, provider, pool):
        self.provider = provider
        self.pool = pool
        self._state = EndpointState.INITIALIZED
        self._last_updated = datetime.datetime.now()

    @property
    def last_updated(self):
        return self._last_updated

    @property
    def state(self):
        return self._state

    def set_state(self, state):
        if self.state != state:
            LOG.info(_LI("Endpoint '%(ep)s' changing from state"
                         " '%(old)s' to '%(new)s'"),
                     {'ep': self.provider,
                      'old': self.state,
                      'new': state})
        old_state = self._state
        self._state = state

        self._last_updated = datetime.datetime.now()

        return old_state

    def __str__(self):
        return "[%s] %s" % (self.state, self.provider)


class EndpointConnection(object):
    """Simple data holder which contains an endpoint and
    a connection for that endpoint.
    """

    def __init__(self, endpoint, connection):
        self.endpoint = endpoint
        self.connection = connection


class ClusteredAPI(object):
    """Duck types the major HTTP based methods of a
    requests.Session such as get(), put(), post(), etc.
    and transparently proxies those calls to one of
    its managed NSX manager endpoints.
    """
    _HTTP_VERBS = ['get', 'delete', 'head', 'put', 'post', 'patch', 'create']

    def __init__(self, providers,
                 http_provider,
                 min_conns_per_pool=1,
                 max_conns_per_pool=500,
                 keepalive_interval=33):

        self._http_provider = http_provider
        self._keepalive_interval = keepalive_interval

        def _init_cluster(*args, **kwargs):
            self._init_endpoints(providers,
                                 min_conns_per_pool, max_conns_per_pool)

        _init_cluster()

        # reinitialize upon fork for api workers to ensure each
        # process has its own keepalive loops + state
        registry.subscribe(
                _init_cluster, resources.PROCESS, events.AFTER_INIT)

    def _init_endpoints(self, providers,
                        min_conns_per_pool, max_conns_per_pool):
        LOG.debug("Initializing API endpoints")

        def _create_conn(p):
            def _conn():
                # called when a pool needs to create a new connection
                return self._http_provider.new_connection(self, p)
            return _conn

        self._endpoints = {}
        for provider in providers:
            pool = pools.Pool(
                min_size=min_conns_per_pool,
                max_size=max_conns_per_pool,
                order_as_stack=True,
                create=_create_conn(provider))

            endpoint = Endpoint(provider, pool)
            self._endpoints[provider.id] = endpoint

        # service requests using round robin
        self._endpoint_schedule = itertools.cycle(self._endpoints.values())

        # duck type to proxy http invocations
        for method in ClusteredAPI._HTTP_VERBS:
            setattr(self, method, self._proxy_stub(method))

        conns = greenpool.GreenPool()
        for endpoint in self._endpoints.values():
            conns.spawn(self._validate, endpoint)
        eventlet.sleep(0)
        while conns.running():
            if (self.health == ClusterHealth.GREEN
                    or self.health == ClusterHealth.ORANGE):
                # only wait for 1 or more endpoints to reduce init time
                break
            eventlet.sleep(0.5)

        for endpoint in self._endpoints.values():
            # dynamic loop for each endpoint to ensure connectivity
            loop = loopingcall.DynamicLoopingCall(
                self._endpoint_keepalive, endpoint)
            loop.start(initial_delay=self._keepalive_interval,
                       periodic_interval_max=self._keepalive_interval,
                       stop_on_exception=False)

        LOG.debug("Done initializing API endpoint(s). "
                  "API cluster health: %s", self.health)

    def _endpoint_keepalive(self, endpoint):
        delta = datetime.datetime.now() - endpoint.last_updated
        if delta.seconds >= self._keepalive_interval:
            # TODO(boden): backoff on validation failure
            self._validate(endpoint)
            return self._keepalive_interval
        return self._keepalive_interval - delta.seconds

    @property
    def providers(self):
        return [ep.provider for ep in self._endpoints.values()]

    @property
    def endpoints(self):
        return copy.copy(self._endpoints)

    @property
    def http_provider(self):
        return self._http_provider

    @property
    def health(self):
        down = 0
        up = 0
        for endpoint in self._endpoints.values():
            if endpoint.state != EndpointState.UP:
                down += 1
            else:
                up += 1

        if down == len(self._endpoints):
            return ClusterHealth.RED
        return (ClusterHealth.GREEN
                if up == len(self._endpoints)
                else ClusterHealth.ORANGE)

    def _validate(self, endpoint):
        try:
            with endpoint.pool.item() as conn:
                self._http_provider.validate_connection(self, endpoint, conn)
                endpoint.set_state(EndpointState.UP)
        except Exception as e:
            endpoint.set_state(EndpointState.DOWN)
            LOG.warning(_LW("Failed to validate API cluster endpoint "
                            "'%(ep)s' due to: %(err)s"),
                        {'ep': endpoint, 'err': e})

    def _select_endpoint(self):
        # check for UP state until exhausting all endpoints
        seen, total = 0, len(self._endpoints.values())
        while seen < total:
            endpoint = next(self._endpoint_schedule)
            if endpoint.state == EndpointState.UP:
                return endpoint
            seen += 1

    def endpoint_for_connection(self, conn):
        # check all endpoint pools
        for endpoint in self._endpoints.values():
            if (conn in endpoint.pool.channel.queue or
                    conn in endpoint.pool.free_items):
                return endpoint

    @property
    def cluster_id(self):
        return ','.join([str(ep.provider.url)
                         for ep in self._endpoints.values()])

    @contextlib.contextmanager
    def connection(self):
        with self.endpoint_connection() as conn_data:
            yield conn_data.connection

    @contextlib.contextmanager
    def endpoint_connection(self):
        endpoint = self._select_endpoint()
        if not endpoint:
            LOG.debug("All endpoints down for: %s" %
                      [str(ep) for ep in self._endpoints.values()])
            # all endpoints are DOWN and will have their next
            # state updated as per _endpoint_keepalive()
            raise exceptions.ServiceClusterUnavailable(
                cluster_id=self.cluster_id)

        if endpoint.pool.free() == 0:
            LOG.info(_LI("API endpoint %(ep)s at connection "
                         "capacity %(max)s and has %(waiting)s waiting"),
                     {'ep': endpoint,
                      'max': endpoint.pool.max_size,
                      'waiting': endpoint.pool.waiting()})
        # pool.item() will wait if pool has 0 free
        with endpoint.pool.item() as conn:
            yield EndpointConnection(endpoint, conn)

    def _proxy_stub(self, proxy_for):
        def _call_proxy(url, *args, **kwargs):
            return self._proxy(proxy_for, url, *args, **kwargs)
        return _call_proxy

    def _proxy(self, proxy_for, uri, *args, **kwargs):
        # proxy http request call to an avail endpoint
        with self.endpoint_connection() as conn_data:
            conn = conn_data.connection
            endpoint = conn_data.endpoint

            # http conn must support requests style interface
            do_request = getattr(conn, proxy_for)

            if not uri.startswith('/'):
                uri = "/%s" % uri
            url = "%s%s" % (endpoint.provider.url, uri)
            try:
                LOG.debug("API cluster proxy %s %s to %s",
                          proxy_for.upper(), uri, url)
                # call the actual connection method to do the
                # http request/response over the wire
                response = do_request(url, *args, **kwargs)
                endpoint.set_state(EndpointState.UP)

                return response
            except Exception as e:
                LOG.warning(_LW("Request failed due to: %s"), e)
                if not self._http_provider.is_connection_exception(e):
                    # only trap and retry connection errors
                    raise e
                endpoint.set_state(EndpointState.DOWN)
                LOG.debug("Connection to %s failed, checking additional "
                          "endpoints" % url)
                # retry until exhausting endpoints
                return self._proxy(proxy_for, uri, *args, **kwargs)


class NSXClusteredAPI(ClusteredAPI):
    """Extends ClusteredAPI to get conf values and setup the
    NSX v3 cluster.
    """

    def __init__(self,
                 username=None,
                 password=None,
                 retries=None,
                 insecure=None,
                 ca_file=None,
                 concurrent_connections=None,
                 http_timeout=None,
                 http_read_timeout=None,
                 conn_idle_timeout=None,
                 http_provider=None):
        self.username = username or cfg.CONF.nsx_v3.nsx_api_user
        self.password = password or cfg.CONF.nsx_v3.nsx_api_password
        self.retries = retries or cfg.CONF.nsx_v3.http_retries
        self.insecure = insecure or cfg.CONF.nsx_v3.insecure
        self.ca_file = ca_file or cfg.CONF.nsx_v3.ca_file
        self.conns_per_pool = (concurrent_connections or
                               cfg.CONF.nsx_v3.concurrent_connections)
        self.http_timeout = http_timeout or cfg.CONF.nsx_v3.http_timeout
        self.http_read_timeout = (http_read_timeout or
                                  cfg.CONF.nsx_v3.http_read_timeout)
        self.conn_idle_timeout = (conn_idle_timeout or
                                  cfg.CONF.nsx_v3.conn_idle_timeout)

        self._http_provider = http_provider or NSXRequestsHTTPProvider()

        super(NSXClusteredAPI, self).__init__(
            self._build_conf_providers(),
            self._http_provider,
            max_conns_per_pool=self.conns_per_pool,
            keepalive_interval=self.conn_idle_timeout)

        LOG.debug("Created NSX clustered API with '%s' "
                  "provider", self._http_provider.provider_id)

    def _build_conf_providers(self):

        def _schemed_url(uri):
            uri = uri.strip('/')
            return urlparse.urlparse(
                uri if uri.startswith('http') else
                "%s://%s" % (self._http_provider.default_scheme, uri))

        conf_urls = cfg.CONF.nsx_v3.nsx_api_managers[:]
        urls = []
        providers = []

        for conf_url in conf_urls:
            conf_url = _schemed_url(conf_url)
            if conf_url in urls:
                LOG.warning(_LW("'%s' already defined in configuration file. "
                                "Skipping."), urlparse.urlunparse(conf_url))
                continue
            urls.append(conf_url)
            providers.append(Provider(
                conf_url.netloc, urlparse.urlunparse(conf_url)))
        return providers
