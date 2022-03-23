from typing import List

from helper.helper import bytes_to_bit_field, little_endian_to_int, read_varint
from merkleTree.merkleTree import MerkleTree


class MerkleBlock:
    def __init__(
            self, version: int,
            prev_block: bytes,
            merkle_root: bytes,
            timestamp: int,
            bits: bytes,
            nonce: bytes,
            total: int,
            hashes: List[bytes],
            flags: bytes):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.total = total
        self.hashes = hashes
        self.flags = flags

    def __repr__(self) -> str:
        result = 'MerkleBlock: \n - version: {}\n - prev_block: {}\n - merkle_root: {}\n - timestamp: {}\n - bits: {}\n - nonce: {}'.format(
            self.version,
            self.prev_block,
            self.merkle_root,
            self.timestamp,
            self.bits,
            self.nonce
        )
        result += '\n{}\n'.format(self.total)
        for h in self.hashes:
            result += '\t{}\n'.format(h.hex())
        result += '{}'.format(self.flags.hex())

    @classmethod
    def parse(cls, s) -> 'MerkleBlock':
        '''
        Takes a byte stream and parses a merkle block. 
        Returns a Merkle Block object
        '''
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        total = little_endian_to_int(s.read(4))
        hashes_len = read_varint(s)
        hashes = []
        for _ in range(hashes_len):
            hashes.append(s.read(32)[::-1])
        flags_len = read_varint(s)
        flags = s.read(flags_len)
        return cls(
            version, prev_block, merkle_root, timestamp, bits, nonce,
            total, hashes, flags
        )

    def is_valid(self) -> bool:
        h = [hash[::-1] for hash in self.hashes]
        m_t = MerkleTree(self.total)
        m_r = m_t.populate_tree(bytes_to_bit_field(self.flags), h)
        return m_r[::-1] == self.merkle_root
