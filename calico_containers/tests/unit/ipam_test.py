# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from netaddr import IPNetwork, IPAddress
from nose.tools import *
from mock import patch, ANY, call, Mock
import unittest
import json
from etcd import EtcdResult, Client, EtcdAlreadyExist, EtcdKeyNotFound

from pycalico.ipam import IPAMClient, BlockReaderWriter
from pycalico.block import AllocationBlock
from pycalico.datastore_datatypes import IPPool
from block_test import _test_block_empty_v4

network = IPNetwork("192.168.25.0/24")


class TestIPAMClient(unittest.TestCase):

    def setUp(self):
        self.client = IPAMClient()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign(self):
        """
        Mainline test of auto assign.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return ["10.11.12.0/24", "10.11.45.0/24"]

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_1st_block_full(self):
        """
        Test auto assign when 1st block is full.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return ["10.11.12.0/24", "10.11.45.0/24"]

        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(256, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.45.0")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_span_blocks(self):
        """
        Test auto assign when 1st block has fewer than requested addresses.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return ["10.11.12.0/24", "10.11.45.0/24"]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.254"),
                               IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.0"),
                               IPAddress("10.11.45.1")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_not_enough_addrs(self):
        """
        Test auto assign when there aren't enough addresses, and no free
        blocks.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return ["10.11.12.0/24", "10.11.45.0/24"]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block has 1 free address.
        block1 = _test_block_empty_v4()
        _ = block1.auto_assign(255, None, {}, affinity_check=False)
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.254"),
                               IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.255")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_cas_fails(self):
        """
        Test auto assign when 1st block compare-and-swap fails.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return ["10.11.12.0/24", "10.11.45.0/24"]

        # 1st read, 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd read, 1st block has 1 free addresses.
        _ = block0.auto_assign(1, None, {}, affinity_check=False)
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result2 = Mock(spec=EtcdResult)
        m_result2.value = block1.to_json()

        # Read three times, update 3 times.
        self.m_etcd_client.read.side_effect = [m_result0, m_result1, m_result2]
        self.m_etcd_client.update.side_effect = [EtcdAlreadyExist(),
                                                 None,
                                                 None]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.0"),
                               IPAddress("10.11.45.1"),
                               IPAddress("10.11.45.2")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_no_blocks(self):
        """
        Test auto assign when we haven't allocated blocks yet, but there are
        free blocks available.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return []

        def m_get_ip_pools(self, version):
            return [IPPool("192.168.0.0/16")]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            (ipv4s, ipv6s) = self.client.auto_assign(4, 0, None, {})
            assert_list_equal([IPAddress("192.168.0.0"),
                               IPAddress("192.168.0.1"),
                               IPAddress("192.168.0.2"),
                               IPAddress("192.168.0.3")], ipv4s)


    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign(self):
        """
        Mainline test of assign().
        """

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        ip0 = IPAddress("10.11.12.55")
        self.client.assign(ip0, None, {})
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_cas_fails(self):
        """
        Test assign() when the compare-and-swap fails.
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        # First update fails, then succeeds.
        self.m_etcd_client.update.side_effect = [EtcdAlreadyExist(),
                                                 None]

        ip0 = IPAddress("10.11.12.55")
        self.client.assign(ip0, None, {})
        self.m_etcd_client.update.assert_has_calls([call(m_result0),
                                                    call(m_result1)])

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_new_block(self):
        """
        Test assign() when address is in a block that hasn't been written.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # block doesn't exist.
        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign(ip0, None, {})

        # Verify we wrote a new block
        assert_equal(self.m_etcd_client.write.call_count, 1)
        (args, kwargs) = self.m_etcd_client.write.call_args
        json_dict = json.loads(args[1])
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)
        assert_dict_equal({"prevExist": False}, kwargs)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_new_block_cas_error(self):
        """
        Test assign() when address is in a new block.

        Order of events:
            1 Attempt to read the block.  It doesn't exist.
            2 Attempt to write a new block --- false because someone else wrote
              it before us.
            3 Re-read the block.
            4 Compare-and-swap new allocation with read from 3.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # 2nd read.
        block = _test_block_empty_v4()
        block.assign(IPAddress("10.11.12.56"), None, {})
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()

        # 1st read error, second read gets block.
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result1]

        # Write fails, but CAS succeeds.
        self.m_etcd_client.write.side_effect = EtcdAlreadyExist()

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign(ip0, None, {})

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_not_in_pools(self):
        """
        Test assign() when address is not in configured pools.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # block doesn't exist.
        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.12.12.55")
            assert_raises(ValueError, self.client.assign, ip0, None, {})

        # Verify we did not write anything.
        assert_false(self.m_etcd_client.write.called)
        assert_false(self.m_etcd_client.update.called)


class TestBlockReaderWriter(unittest.TestCase):

    def setUp(self):
        self.client = BlockReaderWriter()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    def test_get_affine_blocks(self):
        """
        Test _get_affine_blocks mainline.
        """
        expected_ids = ["192.168.3.0/24", "192.168.5.0/24"]

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in expected_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_empty(self):
        """
        Test _get_affine_blocks when there are no stored blocks.
        """
        expected_ids = []

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            result.children = iter([])
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_key_error(self):
        """
        Test _get_affine_blocks when the host key doesn't exist.
        """
        expected_ids = []

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_pool(self):
        """
        Test _get_affine_blocks when filtering by IPPool
        """
        expected_ids = ["10.10.1.0/24"]
        returned_ids = ["192.168.3.0/24", "10.10.1.0/24"]

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in returned_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        ip_pool = IPPool(IPNetwork("10.0.0.0/8"))
        block_ids = self.client._get_affine_blocks("test_host", 4, ip_pool)
        assert_list_equal(block_ids, expected_ids)

