from abc import abstractclassmethod
from base64 import encode
from io import BytesIO
from random import randint
import time
from typing import List, Tuple

from src.block.block import Block
from src.helper.helper import encode_varint, int_to_little_endian, little_endian_to_int, read_varint

TX_DATA_TYPE = 1
BLOCK_DATA_TYPE = 2
FILTERED_BLOCK_DATA_TYPE = 3
COMPACT_BLOCK_DATA_TYPE = 4


class Message:
    command: bytes

    @abstractclassmethod
    def serialize(self) -> bytes:
        pass


class VersionMessage(Message):
    command = b'version'

    # ip is only ipv4
    def __init__(self, version: int = 70015, services: int = 0, timestamp: int = None,
                 receiver_services: int = 0, receiver_ip: bytes = b'\x00\x00\x00\x00', receiver_port: int = 8333,
                 sender_services: int = 0, sender_ip: bytes = b'\x00\x00\x00\x00', sender_port: int = 8333,
                 nonce: bytes = None, user_agent: bytes = b'/programmingbitcoin:0.1/',
                 latest_block: int = 0, relay: bool = False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp

        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port

        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port

        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self) -> bytes:
        '''Serialize this message to send over the network'''
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)

        result += int_to_little_endian(self.receiver_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.receiver_ip
        result += self.receiver_port.to_bytes(2, 'big')

        result += int_to_little_endian(self.sender_services, 8)
        result += b'\x00' * 10 + b'\xff\xff' + self.sender_ip
        result += self.sender_port.to_bytes(2, 'big')

        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        result += bytes([self.relay])

        return result

    @classmethod
    def parse(cls, s: BytesIO) -> 'VersionMessage':
        version = little_endian_to_int(s.read(4))
        services = little_endian_to_int(s.read(8))
        timestamp = little_endian_to_int(s.read(8))

        receiver_services = little_endian_to_int(s.read(8))
        receiver_ip = s.read(16)[-4:]
        receiver_port = int.from_bytes(s.read(2), 'big')

        sender_services = little_endian_to_int(s.read(8))
        sender_ip = s.read(16)[-4:]
        sender_port = int.from_bytes(s.read(2), 'big')

        nonce = s.read(8)
        user_agent_len = read_varint(s)
        user_agent = s.read(user_agent_len)
        latest_block = little_endian_to_int(s.read(4))
        relay_byte = s.read(1)
        if relay_byte == b'\x01':
            relay = True
        elif relay_byte == b'\x00':
            relay = False
        else:
            raise SyntaxError('Relay is invalid')
        return cls(
            version, services, timestamp,
            receiver_services, receiver_ip, receiver_port,
            sender_services, sender_ip, sender_port,
            nonce, user_agent, latest_block, relay
        )


class VerAckMessage(Message):
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s: BytesIO = None) -> 'VerAckMessage':
        return cls()

    def serialize(self) -> bytes:
        return b''


class PingMessage(Message):
    command = b'ping'

    def __init__(self, nonce: bytes):
        self.nonce = nonce

    @classmethod
    def parse(cls, s: BytesIO) -> 'PingMessage':
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self) -> bytes:
        return self.nonce


class PongMessage(Message):
    command = b'pong'

    def __init__(self, nonce: bytes):
        self.nonce = nonce

    @classmethod
    def parse(cls, s: BytesIO) -> 'PongMessage':
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self) -> bytes:
        return self.nonce


class GetHeadersMessage(Message):
    command = b'getheaders'

    def __init__(self, version: int = 70015, num_hashes: int = 1,
                 start_block: bytes = None, end_block: bytes = None):
        self.version = version
        self.num_hashes = num_hashes
        if start_block is None:
            raise RuntimeError(
                'A start Block is required to GetHeadersMessage')
        self.start_block = start_block
        if end_block is None:
            self.end_block = b'\x00' * 32
        else:
            self.end_block = end_block

    @classmethod
    def parse(cls, s: BytesIO) -> 'GetHeadersMessage':
        version = little_endian_to_int(s.read(4))
        num_hashes = read_varint(s)
        start_block = s.read(32)[::-1]
        end_block = s.read(32)[::-1]
        return cls(
            version,
            num_hashes,
            start_block,
            end_block
        )

    def serialize(self) -> bytes:
        '''Serialize this message to send over the network.'''
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result


class HeadersMessage(Message):
    command = b'headers'

    def __init__(self, blocks: List[Block]):
        self.blocks = blocks

    @classmethod
    def parse(cls, s: BytesIO) -> 'HeadersMessage':
        '''Returns Block Headers'''
        num_block = read_varint(s)
        blocks: List[Block] = []
        for _ in range(num_block):
            blocks.append(Block.parse(s))
            num_txs = read_varint(s)
            if num_txs != 0:
                raise SyntaxError('Number of txs not 0')
        return cls(blocks)

    def serialize(self) -> bytes:
        result = b''
        result += encode_varint(len(self.blocks))
        for b in self.blocks:
            result += b.serialize()
            result += b'\x00'
        return result


class GenericMessage(Message):
    def __init__(self, command: bytes, payload: bytes):
        self.command = command
        self.payload = payload

    def serialize(self) -> bytes:
        return self.payload


class GetDataMessage(Message):
    command = b'getdata'

    def __init__(self) -> None:
        self.data: List[Tuple[int, bytes]] = []

    def add_data(self, data_type: int, identifier: bytes):
        self.data.append((data_type, identifier))

    @classmethod
    def parse(cls, s: BytesIO) -> 'GetDataMessage':
        data_len = read_varint(s)
        me = cls()
        for _ in range(data_len):
            data_type = little_endian_to_int(s.read(4))
            identifier = s.read(32)[::-1]
            me.add_data(data_type, identifier)
        return me

    def serialize(self) -> bytes:
        result = encode_varint(len(self.data))
        for (data_type, identifier) in self.data:
            result += int_to_little_endian(data_type, 4)
            result += identifier[::-1]
        return result
