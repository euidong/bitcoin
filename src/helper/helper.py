import hashlib
from unittest import TestCase, TestSuite, TextTestRunner
from io import BytesIO

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
TWO_WEEKS = 60 * 60 * 24 * 14


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


def read_variant(s: BytesIO) -> int:
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


def encode_variant(i: int) -> bytes:
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
    return target_to_bits(new_target)
