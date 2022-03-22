from io import BytesIO

from src.helper.helper import hash256, int_to_little_endian, little_endian_to_int


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
TESTNET_NETWORK_MAGIC = b'\x0b\x11\x09\x07'


class Envelope:
    def __init__(self, command: bytes, payload: bytes, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self) -> str:
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex()
        )

    @classmethod
    def parse(cls, s: BytesIO, testnet=False) -> 'Envelope':
        '''Takes a stream and creates a Envelope'''
        magic = s.read(4)
        if testnet and magic != TESTNET_NETWORK_MAGIC:
            raise SyntaxError('Network magic is invalid')
        elif not testnet and magic != NETWORK_MAGIC:
            raise SyntaxError('Netowkr magic is invalid')
        cmd = s.read(12).strip(b'\x00')
        payload_len = little_endian_to_int(s.read(4))
        check_sum = s.read(4)
        payload = s.read(payload_len)
        if hash256(payload)[:4] != check_sum:
            raise SyntaxError('CheckSum is invalid')
        return cls(cmd, payload, testnet)

    def serialize(self) -> bytes:
        '''Returns the byte serialization of the entire network message'''
        result = self.magic
        result += self.command + (b'\x00' * (12 - len(self.command)))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result

    def stream(self) -> BytesIO:
        '''Returns a stream for parsing the payload'''
        return BytesIO(self.payload)
