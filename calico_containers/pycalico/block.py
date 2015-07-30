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

from netaddr import IPAddress, IPNetwork
import socket
import json

BITS_BY_VERSION = {4: 32, 6: 128}
BLOCK_SIZE_BITS = 8
BLOCK_PREFIXLEN = {4: 32 - BLOCK_SIZE_BITS,
                   6: 128 - BLOCK_SIZE_BITS}
BLOCK_SIZE = 2 ** BLOCK_SIZE_BITS
PREFIX_MASK = {4: (IPAddress("255.255.255.255") ^ (BLOCK_SIZE - 1)),
               6: (IPAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") ^
                   (BLOCK_SIZE - 1))}
my_hostname = socket.gethostname()


class AllocationBlock(object):
    """
    A block of IP addresses from which to allocate for IPAM clients.

    Blocks are identified by IP prefix.  Each block is a single, keyed object
    in etcd and the value of the block object in the datastore encodes all the
    allocations for all the IP addresses within that prefix.

    Thus, allocations and releases of IP addresses correspond to changes in the
    block's value.  Compare-and-swap atomicity is used to ensure allocations
    and releases are consistent operations.
    """
    CIDR = "cidr"
    AFFINITY = "affinity"
    HOST_AFFINITY_T = "host:%s"
    ALLOCATIONS = "allocations"
    ATTRIBUTES = "attributes"
    ATTR_PRIMARY = "primary"
    ATTR_SECONDARY = "secondary"

    def __init__(self, cidr_prefix, host_affinity):
        assert isinstance(cidr_prefix, IPNetwork)
        assert cidr_prefix.cidr == cidr_prefix

        # Make sure the block is the right size.
        assert cidr_prefix.prefixlen == (BITS_BY_VERSION[cidr_prefix.version] -
                                         BLOCK_SIZE_BITS)
        self.cidr = cidr_prefix
        self.db_result = None

        self.host_affinity = host_affinity
        """
        Both to minimize collisions, where multiple hosts attempt to change a
        single block, and to support route aggregation, each block has affinity
        to a single Calico host.  That host does not hold exclusive rights to
        modify the block; any host may still do that.  The host with affinity
        simply uses the block as the place where it first searches if the user
        asked to have the IP assigned automatically.
        """

        self.allocations = [None] * BLOCK_SIZE
        """
        A fixed length array with one entry for every address in the block.
        None means unallocated.  A non-negative integer indicates the address
        is allocated, and is the index into the `attributes` array for the
        attributes assigned to the allocation.
        """

        self.attributes = []
        """
        Dictionaries of attributes for allocations.
        """

    def get_block_id(self):
        """
        Return the CIDR block_id for this block.
        :return: String representation of the CIDR prefix.
        """
        return str(self.cidr)

    def to_json(self):
        """
        Convert to a JSON representation for writing to etcd.
        """

        json_dict = {AllocationBlock.CIDR: str(self.cidr),
                     AllocationBlock.AFFINITY:
                         AllocationBlock.HOST_AFFINITY_T % self.host_affinity,
                     AllocationBlock.ALLOCATIONS: self.allocations,
                     AllocationBlock.ATTRIBUTES: self.attributes}
        return json.dumps(json_dict)

    @classmethod
    def from_etcd_result(cls, etcd_result):
        """
        Convert a JSON representation into an instance of AllocationBlock.
        """
        json_dict = json.loads(etcd_result.value)
        cidr_prefix = IPNetwork(json_dict[AllocationBlock.CIDR])

        # Parse out the host.  For now, it's in the form host:<hostname>
        affinity = json_dict[AllocationBlock.AFFINITY]
        assert affinity[:5] == "host:"
        host_affinity = affinity[5:]

        block = cls(cidr_prefix, host_affinity)
        block.db_result = etcd_result

        # Process & check allocations
        allocations = json_dict[AllocationBlock.ALLOCATIONS]
        assert len(allocations) == BLOCK_SIZE
        block.allocations = allocations

        # Process & check attributes
        attributes = json_dict[AllocationBlock.ATTRIBUTES]
        block.attributes = attributes
        assert (block._verify_attributes())

        return block

    def update_result(self):
        """
        Return the EtcdResult with any changes to the object written to
        result.value.
        :return:
        """
        self.db_result.value = self.to_json()
        return self.db_result

    def auto_assign(self, num, primary_key, attributes, affinity_check=True):
        """
        Automatically pick and assign the given number of IP addresses.

        :param num: Number of addresses to request
        :param primary_key: allocation primary key for this request.  You can
        query this key using get_assignments_by_key() or release all addresses
        with this key using release_by_key().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param affinity_check: If true, verify that this block's affinity is this
        host and throw a NoHostAffinityWarning if it isn't.  Set to false to
        disable this check.
        :return: List of assigned addresses.  When the block is at or near
        full, this method may return fewer than requested IPs.
        """
        assert num >= 0

        if affinity_check and my_hostname != self.host_affinity:
            raise NoHostAffinityWarning("Host affinity is %s" %
                                        self.host_affinity)

        ordinals = []
        # Walk the allocations until we find enough.
        for o in xrange(BLOCK_SIZE):
            if len(ordinals) == num:
                break
            if self.allocations[o] is None:
                ordinals.append(o)

        ips = []
        if ordinals:
            # We found some addresses, now we need to set up attributes.
            attr_index = self._find_or_add_attrs(primary_key, attributes)

            # Perform the allocation.
            for o in ordinals:
                assert self.allocations[o] is None
                self.allocations[o] = attr_index

                # Convert ordinal to IP.
                ip = IPAddress(self.cidr.first + o, version=self.cidr.version)
                ips.append(ip)
        return ips

    def assign(self, address, primary_key, attributes):
        """
        Assign the given address.  Throws AlreadyAssignedError if the address
        is taken.

        :param address: IPAddress to assign.
        :param primary_key: allocation primary key for this request.  You can
        query this key using get_assignments_by_key() or release all addresses
        with this key using release_by_key().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :return: None.
        """
        assert isinstance(address, IPAddress)
        # Convert to an ordinal
        ordinal = int(address - self.cidr.first)
        assert 0 <= ordinal <= BLOCK_SIZE, "Address not in block."

        # Check if allocated
        if self.allocations[ordinal] is not None:
            raise AlreadyAssignedError("%s is already assigned in block %s" % (
                address, self.cidr))

        # Set up attributes
        attr_index = self._find_or_add_attrs(primary_key, attributes)
        self.allocations[ordinal] = attr_index
        return

    def count_free_addresses(self):
        """
        Count the number of free addresses in this block.
        :return: Number of free addresses.
        """
        count = 0
        for a in self.allocations:
            if a is None:
                count += 1
        return count

    def _find_or_add_attrs(self, primary_key, attributes):
        """
        Check if the key and attributes match existing and return the index, or
        if they don't exist, add them and return the index.
        """
        assert json.dumps(attributes), \
            "Attributes aren't JSON serializable."
        attr = {AllocationBlock.ATTR_PRIMARY: primary_key,
                AllocationBlock.ATTR_SECONDARY: attributes}
        attr_index = None
        for index, exist_attr in enumerate(self.attributes):
            if cmp(attr, exist_attr) == 0:
                attr_index = index
                break
        if attr_index is None:
            # Attributes are new, add them.
            attr_index = len(self.attributes)
            self.attributes.append(attr)
        return attr_index

    def _verify_attributes(self):
        """
        Verify the integrity of attribute & allocations.

        This is a debug-only function to detect errors.
        """
        attr_indexes = set(self.allocations)
        max_attr = max(attr_indexes)
        if max_attr is None:
            # Empty block.  Just assert empty attrs and exit.
            assert len(self.attributes) == 0
            return True

        # All attributes present?
        assert len(self.attributes) == max_attr + 1

        # All attributes actually used?
        for x in xrange(max_attr + 1):
            assert x in attr_indexes

        # All assignments point to attributes or None.
        for assignment in self.allocations:
            assert assignment is None or isinstance(assignment, int)
        return True


def get_block_id_for_address(address):
    """
    Get the block ID to which a given address belongs.
    :param address: IPAddress
    """
    prefix = PREFIX_MASK[address.version] & address
    prefixlen = BITS_BY_VERSION[address.version] - BLOCK_SIZE_BITS
    block_id = "%s/%s" %(prefix, prefixlen)
    return block_id


class NoHostAffinityWarning(Exception):
    """
    Tried to auto-assign in a block this host didn't own.  This exection can be
    explicitly disabled.
    """
    pass


class AlreadyAssignedError(Exception):
    """
    Tried to assign an address, but the address is already taken.
    """
    pass
