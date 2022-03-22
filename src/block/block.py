from io import BytesIO
from time import time

from src.helper.helper import bits_to_target, hash256, int_to_little_endian, little_endian_to_int


class Block:
    def __init__(
            self, version: int,
            prev_block: bytes,
            merkle_root: bytes,
            timestamp: int,
            bits: bytes,
            nonce: bytes):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def __repr__(self) -> str:
        return 'Block: \n - version: {}\n - prev_block: {}\n - merkle_root: {}\n - timestamp: {}\n - bits: {}\n - nonce: {}'.format(
            self.version,
            self.prev_block,
            self.merkle_root,
            self.timestamp,
            self.bits,
            self.nonce
        )

    @classmethod
    def parse(cls, s: BytesIO) -> 'Block':
        '''
        Takes a byte stream and parses a block.
        Returns a Block object
        '''
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self) -> bytes:
        '''Returns the 80 bytes Block header'''
        result = b''
        result += int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self) -> bytes:
        '''Returns the hash256 interpreted little endian of the Block'''
        b = self.serialize()
        return hash256(b)[::-1]

    def bip9(self) -> bool:
        '''Returns whether this Block is signaling readiness for BIP0009'''
        return self.version >> 29 == 0b001

    def bip91(self) -> bool:
        '''Returns whether this Block is signaling readiness for BIP0091'''
        return self.version >> 4 & 1

    def bip141(self) -> bool:
        '''Returns whether this Block is signaling readiness for BIP0141'''
        return self.version >> 1 & 1

    def target(self) -> int:
        '''Returns the proof-of-work target based on the bits'''
        return bits_to_target(self.bits)

    def difficulty(self) -> int:
        '''Returns the Block difficulty based on the bits'''
        return 0xffff * pow(0x100, 0x1d-3) / self.target()

    def check_pow(self) -> bool:
        '''Returns whether this Block satisfies proof of work'''
        proof = int.from_bytes(self.hash(), 'big')
        return proof < self.target()
