import hashlib
from typing import List, Union
from unittest import TestSuite, TextTestRunner
from io import BytesIO

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256**(0x1d - 3)


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
    # now, this function looks like decode_address.
    # TODO: now, decode base 58 is fixed 25 bytes.
    combined = num.to_bytes(25, 'big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address:{} {}'.format(
            checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]


def little_endian_to_int(b: bytes) -> int:
    '''get little endian bytes and return int'''
    return int.from_bytes(b, 'little')


def int_to_little_endian(n: int, length: int) -> bytes:
    '''get int, length and return bytes'''
    return int.to_bytes(n, length, 'little')


def read_varint(s: BytesIO) -> int:
    '''return integer from bytes stream'''
    i = s.read(1)[0]
    if i < 0xfd:
        return i
    elif i == 0xfd:
        i = s.read(2)
    elif i == 0xfe:
        i = s.read(4)
    elif i == 0xff:
        i = s.read(8)
    return little_endian_to_int(i)


def encode_varint(i: int) -> bytes:
    '''encodes a integer as a variant(bytes)'''
    if i < 0xfd:  # 2^8 - 3
        return bytes([i])
    if i < 0x10000:  # 2^16 - 1
        return b'\xfd' + int_to_little_endian(i, 2)
    if i < 0x100000000:  # 2^32 - 1
        return b'\xfe' + int_to_little_endian(i, 4)
    if i < 0x10000000000000000:  # 2^64 - 1
        return b'\xff' + int_to_little_endian(i, 8)
    raise ValueError('Too big to send {}'.format(i))


def h160_to_p2pkh_address(h160: bytes, testnet=False) -> str:
    '''
    Takes a byte sequence hash160 and returns a p2pkh address string
    p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    use encode_base58_checksum to get the address
    '''
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160: bytes, testnet=False) -> str:
    '''
    Takes a byte sequence hash160 and returns a p2sh address string
    p2sh ahas a prefix of b'\x05' for mainnet, b'\xc4' for testnet
    use encode_base58_checksum to get the address
    '''
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)


def bits_to_target(bits: bytes) -> int:
    '''Turns bits into a target(large 256-bit integer)'''
    exp = bits[-1]
    coef = little_endian_to_int(bits[:-1])
    return coef * (0x100 ** (exp - 3))


def target_to_bits(target: int) -> bytes:
    '''Turns a target integer back into bits'''
    b = target.to_bytes(32, 'big')
    b = b.lstrip(b'\x00')
    if b[0] < 0x80:
        exp = len(b)
        coef = b[:3]
    else:
        exp = len(b) + 1
        coef = b'\x00' + b[:2]
    return coef[::-1] + bytes([exp])


def calculate_new_bits(previous_bits: bytes, time_differential: int) -> bytes:
    '''Calculates the new bits given a 2016-block time differential and the previous bits'''
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    elif time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4

    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    new_target = min(new_target, MAX_TARGET)

    return target_to_bits(new_target)


def merkle_parent(hash1: bytes, hash2: bytes) -> bytes:
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes: List[bytes]) -> List[bytes]:
    hs = hashes[:]
    if len(hs) % 2:
        hs.append(hs[-1])
    parent_level = []
    for idx in range(0, len(hs), 2):
        parent_level.append(merkle_parent(hs[idx], hs[idx + 1]))
    return parent_level


def merkle_root(hashes: Union[bytes, List[bytes]]) -> bytes:
    if type(hashes) == bytes:
        return hashes

    hs = hashes[:]
    while len(hs) != 1:
        hs = merkle_parent_level(hs)
    return hs[0]


def bit_field_to_bytes(bit_field: List[int]) -> bytes:
    if len(bit_field) % 8 != 0:
        raise RuntimeError('bit_field length must be 8')
    bytes_int_ary = []
    for idx in range(0, len(bit_field), 8):
        v = 0
        for i in range(8):
            if bit_field[idx + i]:
                v |= 1 << i
        bytes_int_ary.append(v)
    return bytes(bytes_int_ary)


def bytes_to_bit_field(some_bytes: bytes) -> List[int]:
    bits = []
    for byte in some_bytes:
        for _ in range(8):
            bits.append(byte & 1)
            byte >>= 1
    return bits


def murmur3(data, seed=0):
    '''from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash'''
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | \
             ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | \
             (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64
    # tail
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
    # finalization
    h1 ^= length
    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)
    return h1 & 0xffffffff
