# Copyright 2016 VMware, Inc.
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.services import tags_client

CONF = config.CONF
LOG = logging.getLogger(__name__)
MAX_TAG_LEN = 60


class BaseTagsTest(base.BaseNetworkTest):
    """Base class for Tags Test."""

    @classmethod
    def skip_checks(cls):
        """skip tests if the tags feauture is not enabled."""
        super(BaseTagsTest, cls).skip_checks()
        if not test.is_extension_enabled('tag', 'network'):
            msg = "network tag extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(BaseTagsTest, cls).resource_setup()
        cls.primary_mgr = cls.get_client_manager()
        cls.tags_client = tags_client.get_client(cls.primary_mgr)

    @classmethod
    def resource_cleanup(cls):
        """cleanup resources before handing over to framework."""
        super(BaseTagsTest, cls).resource_cleanup()

    @classmethod
    def list_networks(cls, **filters):
        nets = cls.networks_client.list_networks(**filters)
        return nets.get('networks')

    @classmethod
    def tag_add(cls, network_id, tag, resource_type='network'):
        cls.tags_client.add_tag(resource_type=resource_type,
                                resource_id=network_id,
                                tag=tag)
        network = cls.networks_client.show_network(network_id)
        return network.get('network')

    @classmethod
    def tag_remove(cls, network_id, tag, resource_type='network'):
        cls.tags_client.remove_tag(resource_type=resource_type,
                                   resource_id=network_id,
                                   tag=tag)
        network = cls.networks_client.show_network(network_id)
        return network.get('network')

    @classmethod
    def tag_replace(cls, network_id, tags, resource_type='network'):
        req_body = dict(resource_type=resource_type, resource_id=network_id)
        if type(tags) in (list, tuple, set):
            req_body['tags'] = tags
        else:
            req_body['tags'] = [tags]
        cls.tags_client.replace_tag(**req_body)
        network = cls.networks_client.show_network(network_id)
        return network.get('network')

    def network_add_tag(self, network_id, tag):
        network = self.tag_add(network_id, tag, 'network')
        self.assertIn(tag, network['tags'])
        return network

    def network_remove_tag(self, network_id, tag):
        network = self.tag_remove(network_id, tag, 'network')
        self.assertNotIn(tag, network['tags'])
        return network

    def network_replace_tags(self, network_id, tags=None):
        if tags is None:
            tags = ['a', 'ab', 'abc']
        network = self.tag_replace(network_id, tags, 'network')
        self.assertEqual(len(tags), len(network['tags']))
        for tag in tags:
            self.assertIn(tag, network['tags'])
        return network


class NetworkTagAddTest(BaseTagsTest):
    """neutron tag-add test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagAddTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('0e37a579-aff3-47ba-9f1f-3ac4482fce16')
    def test_add_tags(self):
        """neutron tag-add operations."""
        tags = ['a', 'gold', 'T' * MAX_TAG_LEN]
        network_id = self.net.get('id')
        # check we can add tag one at time
        for tag in tags:
            network = self.network_add_tag(network_id, tag)
        # and all added tags exist.
        for tag in tags:
            self.assertIn(tag, network['tags'])

    @test.idempotent_id('eb52eac3-5e79-4183-803a-a3d97ceb171d')
    @test.attr(type='negative')
    def test_add_tag_one_char_too_long(self):
        tag_too_long = 'a' * (MAX_TAG_LEN + 1)
        network_id = self.net.get('id')
        self.assertRaises(exceptions.BadRequest,
                          self.network_add_tag,
                          network_id, tag_too_long)

    @test.idempotent_id('d08f3fbe-dc6f-4f3c-b9b2-4d9957884edf')
    @test.attr(type='negative')
    def test_add_tag_empty_one(self):
        network_id = self.net.get('id')
        self.assertRaises(exceptions.NotFound,
                          self.network_add_tag,
                          network_id, '')


class NetworkTagRemoveTest(BaseTagsTest):
    """neutron tag-remove test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagRemoveTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('178fbd96-900f-4c3d-8cd1-5525f4cf2b81')
    def test_remove_tags(self):
        """neutron tag-remove operations."""
        network_id = self.net.get('id')
        tag = 'spinning-tail'
        self.network_add_tag(network_id, tag)
        self.network_remove_tag(network_id, tag)

    @test.idempotent_id('1fe5a8b2-ff5d-4250-b930-21b1a3b48055')
    @test.attr(type='negative')
    def test_remove_all_tags(self):
        network_id = self.net.get('id')
        self.network_replace_tags(network_id)
        req_body = dict(resource_type='network',
                        resource_id=network_id, all=True)
        self.tags_client.remove_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(network['tags']), 0)

    @test.idempotent_id('591337b0-a2e6-4d72-984c-e5b6a6ec12d2')
    @test.attr(type='negative')
    def test_remove_not_exist_tag(self):
        """neutron tag-remove operations."""
        network_id = self.net.get('id')
        tag_not_tagged = 'talking-head'
        self.assertRaises(exceptions.NotFound,
                          self.network_remove_tag,
                          network_id, tag_not_tagged)


class NetworkTagReplaceTest(BaseTagsTest):
    """neutron tag-replace test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagReplaceTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('7d4fb288-2f2d-4f47-84af-be3175b057b5')
    def test_replace_tags(self):
        """neutron tag-replace operations."""
        network_id = self.net.get('id')
        tags = ['east', 'south', 'west', 'north']
        self.network_replace_tags(network_id, tags)
        new_tags = ['BIG', 'small']
        self.network_replace_tags(network_id, new_tags)
        # EQ to remove all
        empty_tags = []
        self.network_replace_tags(network_id, empty_tags)

    @test.idempotent_id('20a05e9e-0b25-4085-b89f-fd5f0c57d2fa')
    @test.attr(type='negative')
    def test_replace_tags_one_char_too_long(self):
        tags_too_long = ['aaa', 'z' * (MAX_TAG_LEN + 1)]
        network_id = self.net.get('id')
        self.assertRaises(exceptions.BadRequest,
                          self.network_replace_tags,
                          network_id, tags_too_long)


class NetworkTagFilterTest(BaseTagsTest):
    """searching networks using tags querying params.

    Four query parameters are supported:

        Q-param             Q-procedure
        ------------        -----------
        tags                x_and_y
        tags-any            x_or_y
        not-tags            not_x_and_y
        not-tags-any        not_x_or_y
    """

    @classmethod
    def resource_setup(cls):
        """setup default values for filtering tests."""
        super(NetworkTagFilterTest, cls).resource_setup()
        cls.a_b_c = ['a', 'ab', 'abc']
        cls.not_tagged_tags = ['talking-head', 'spinning-tail']
        cls._tags = (['east', 'gold', 'production'],
                     ['west', 'silver', 'development'],
                     ['north', 'brown', 'development', 'abc'],
                     ['south', 'brown', 'testing', 'a'],
                     ['west', 'gold', 'production', 'ab'],
                     ['east', 'silver', 'testing'],
                     ['north', 'gold', 'production'],
                     ['south', 'silver', 'testing'])
        cls.QQ = {'router:external': False}
        cls.GG = {}
        for ix in range(0, len(cls._tags)):
            net = cls.create_network()
            tags = cls._tags[ix]
            net = cls.tag_replace(net['id'], tags=tags)
            if not (set(net['tags']) == set(cls._tags[ix])):
                raise Exception(
                    _("tags[%s] are not tag-replace successfully.") % tags)
            net_id = net['id']
            cls.GG[net_id] = set(net['tags'])

    def check_matched_search_list(self, matched_nets, m_net_list, title):
        LOG.info(_("Expected_nets[{0}]: {1}").format(title, m_net_list))
        LOG.info(_("Number of matched_nets: {0}").format(len(matched_nets)))
        self.assertEqual(len(matched_nets), len(m_net_list))
        for net in matched_nets:
            self.assertIn(net['id'], m_net_list)

    @test.idempotent_id('9646af99-7e04-4724-ac54-4a938de764f1')
    def test_tags_only_one_network(self):
        """each tag in self.a_b_c only tag one network."""
        for tag in self.a_b_c:
            filters = {'tags': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 1)

    @test.idempotent_id('5632b745-651a-444f-922d-6434e060991a')
    def test_tags_any_only_one_network(self):
        """each tag in self.a_b_c only tag one network."""
        for tag in self.a_b_c:
            filters = {'tags-any': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 1)

    @test.idempotent_id('a0d8c21b-1ec0-4c6d-b5d8-72baebabde26')
    def test_tags_not_tagged(self):
        """search with tags for tags not being tagged."""
        for tag in self.not_tagged_tags:
            filters = {'tags': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 0)

    @test.idempotent_id('1049eac1-028b-4664-aeb7-c7656240622d')
    def test_tags_any_not_tagged(self):
        """search with tags-any for tags not being tagged."""
        for tag in self.not_tagged_tags:
            filters = {'tags-any': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 0)

    @test.idempotent_id('a9b42503-5dd1-490d-b0c6-673951cc86a1')
    def test_tags(self):
        """find networks having tags (and operation)"""
        tags = ['gold', 'production']
        m_net_list = x_and_y(tags, self.GG)
        filters = {'tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list, 'tags')

    @test.idempotent_id('c38e788d-749e-401a-8bbb-26e36a7b573f')
    def test_tags_any(self):
        """find networks having tags-any (or operation)"""
        tags = ['gold', 'production']
        m_net_list = x_or_y(tags, self.GG)
        filters = {'tags-any': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list, 'tags-any')

    @test.idempotent_id('e7bb1cea-3271-418c-bfe2-038fff6187e6')
    def test_not_tags(self):
        """find networks not having not-tags (and operation)"""
        tags = ['gold', 'production']
        m_net_list = not_x_and_y(tags, self.GG)
        filters = {'not-tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list, 'not-tags')

    @test.idempotent_id('c36a1d00-c131-4297-86c1-a3fc06c61629')
    def test_not_tags_any(self):
        """find networks not having not-tags-any (or operation)"""
        tags = ['gold', 'production']
        m_net_list = not_x_or_y(tags, self.GG)
        filters = {'not-tags-any': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list, 'not-tags-any')

    @test.idempotent_id('4345e944-6b2b-4106-a208-ce07cefe764f')
    def test_tags_any_not_tags(self):
        """find networks having tags-any and not-tags."""
        tags = ['gold', 'production']
        not_tags = ['west']
        m_net_list = not_x_and_y(not_tags, self.GG,
                                 x_or_y(tags, self.GG))
        filters = {'tags-any': tags, 'not-tags': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list,
                                       'tags-any & not-tags')

    @test.idempotent_id('0d635ba7-5c94-4a24-b7a8-d3b413d1ec83')
    @decorators.skip_because(bug="1611054")
    def test_tags_tags_any(self):
        """finding networks using tags and tags-any."""
        tags = ['production']
        tags_any = ['east', 'west']
        m_net_list = x_or_y(tags_any, self.GG,
                            x_and_y(tags, self.GG))
        filters = {'tags': tags, 'tags-any': tags_any}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list,
                                       'tags & tags-any')

    @test.idempotent_id('2067a8fc-2d7b-4085-a6c2-7e454f6f26f3')
    def test_tags_not_tags_any(self):
        """finding networks using tags and not-tags-any."""
        tags = ['gold', 'production']
        not_tags = ['east', 'west', 'silver']
        m_net_list = not_x_or_y(not_tags, self.GG,
                                x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags-any': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list,
                                       'tags & not-tags-any')

    @test.idempotent_id('f2bbf51c-e32e-4664-a0db-59eed493c3d1')
    def test_tags_not_tags_any2(self):
        """finding networks using tags and not-tags-any."""
        tags = ['gold', 'production']
        not_tags = ['west', 'east']
        m_net_list = not_x_or_y(not_tags, self.GG,
                                x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags-any': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list,
                                       'tags & not-tags-any2')

    @test.idempotent_id('7b17dfa8-f7ac-47c2-b814-35c5ed1c325b')
    def test_tags_not_tags(self):
        """finding networks using tags and not-tags."""
        tags = ['gold', 'production']
        not_tags = ['west']
        m_net_list = not_x_and_y(not_tags, self.GG,
                                 x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list,
                                       'tags & not-tags')

    @test.idempotent_id('f723f717-660b-4d8e-ae9f-014f0a3f812d')
    def test_tags_not_tags_itself(self):
        """"tags and not-tags itself is always an empty set."""
        tags = ['gold', 'production']
        not_x_and_y(tags, self.GG, x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.assertEqual(0, len(nets))


# search/filter methods
# K_sets: Dict of sets
def x_and_y(x_and_y, K_sets, on_keys=None):
    """tags=x_and_y"""
    s_xy = set(x_and_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and s_xy.issubset(S)]
    return xy_s


def not_x_and_y(x_and_y, K_sets, on_keys=None):
    """not-tags=x_and_y"""
    s_xy = set(x_and_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and not s_xy.issubset(S)]
    return xy_s


def x_or_y(x_or_y, K_sets, on_keys=None):
    """tags-any=x_or_y"""
    s_xy = set(x_or_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and len(S & s_xy) > 0]
    return xy_s


def not_x_or_y(x_or_y, K_sets, on_keys=None):
    """not tags-any=x_or_y"""
    s_xy = set(x_or_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and len(S & s_xy) == 0]
    return xy_s
