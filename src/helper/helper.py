import hashlib
from unittest import TestCase, TestSuite, TextTestRunner

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash160(s: bytes) -> bytes:
    '''sha256 followed by ripemd160(20bytes)'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    '''two rounds of sha256(32bytes)'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s: bytes) -> str:
    '''return base58 encoded string data'''
    # <-- this loop and prefix are used for making fixed length.
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    prefix = '1' * count
    # -->
    num = int.from_bytes(s, 'big')
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(b: bytes) -> str:
    '''return base58 encoded data'''
    checksum = hash256(b)[:4]
    return encode_base58(b + checksum)


def decode_base58(s: bytes) -> bytes:
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    # because, address is 25bytes
    # prefix(testnet or not,  1bytes) + hash160(20bytes) + checksum(4bytes)
    # TODO: now, decode base 58 is fixed 25 bytes.
    combined = num.to_bytes(25, 'big')


def little_endian_to_int(b: bytes) -> int:
    '''get little endian bytes and return int'''
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    '''get int, length and return bytes'''
    return int.to_bytes(n, length, 'little')


class HelperTest(TestCase):
    def test_little_endian_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 8), want)
