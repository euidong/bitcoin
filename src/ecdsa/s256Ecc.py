# BitCoin use secp256k1 and group order which was fixed.
# So, We will call BitCoin's ecdsa 's256 ecc'

from bz2 import compress
import hashlib
import hmac
from pickletools import bytes8
from random import randint
from . import ecc
from unittest import TestCase
from ..helper import helper


# Bit Coin's Descrete Elliptic Curve Variables
A: int = 0  # Elliptic Curve variable 1
B: int = 7  # Elliptic Curve variable 2
P: int = 2 ** 256 - 2 ** 32 - 977  # prime number
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141  # Group's Order
# x of Group's representative
Gx: int = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
# y of Group's representative
Gy: int = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8


# secp256k1 Group Field
class S256Field(ecc.FieldElement):
    def __init__(self, num: int, p=None):
        super().__init__(num, P)

    def __repr__(self) -> str:
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self**((P + 1) // 4)


# TODO: Now S256Point have Public Key's logic. So, seperate that methods.
# secp256k1 Elliptic Curve Point
class S256Point(ecc.Point):
    def __init__(self, x: int, y: int, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(S256Field(x), S256Field(y), a, b)
        else:
            super().__init__(x, y, a, b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(Infinite)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coefficient: int) -> 'S256Point':
        coef = coefficient % N
        return super().__rmul__(coef)

    # It only work well when this point is Public Key.
    def verify(self, z: bytes8, sig: 'Signature') -> bool:
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        result = (u * G) + (v * self)
        return result.x.num == sig.r

    # For Point Serialization
    # SEC(Stanadrds for Efficient Cryptography)
    def serialize_sec(self, compressed=True) -> bytes:
        '''returns the binary version of the SEC format'''
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

    @classmethod
    def parse_sec(cls, sec_bin: bytes) -> 'S256Point':
        '''return S256Point(PublicKey) from SEC Binary'''
        # uncompressed
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return cls(x, y)
        # compressed
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        y_square: S256Field = x ** 3 + S256Field(B)
        y_candidate = y_square.sqrt()
        if y_candidate.num % 2 == 0:
            even_y = y_candidate.num
            odd_y = S256Field(P - y_candidate.num)
        else:
            even_y = S256Field(P - y_candidate.num)
            odd_y = y_candidate.num
        is_even = sec_bin[0] == 2
        if is_even:
            return cls(x, even_y)
        else:
            return cls(x, odd_y)

    def hash160(self, compressed=True) -> bytes:
        return helper.hash160(self.serialize_sec(compressed))

    def address(self, compressed=True, testnet=False) -> str:
        '''Return the address string'''
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return helper.encode_base58_checksum(prefix + h160)


G = S256Point(Gx, Gy)


class S256Test(TestCase):
    def test_order(self):
        point = N * G
        self.assertIsNone(point.x)

    def test_pubpoint(self):
        # write a test that tests the public point for the following
        points = (
            # secret, x, y
            (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc,
             0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
            (1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda,
             0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
            (2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da,
             0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
            (2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116,
             0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
        )

        # iterate over points
        for secret, x, y in points:
            # initialize the secp256k1 point (S256Point)
            point = S256Point(x, y)
            # check that the secret*G is the same as the point
            self.assertEqual(secret * G, point)

    def test_verify(self):
        # Public Key
        point = S256Point(
            0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
            0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)

        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60  # hash
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(point.verify(z, Signature(r, s)))

        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(point.verify(z, Signature(r, s)))

    def test_sec(self):
        coefficient = 999**3
        uncompressed = '049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9'
        compressed = '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
        point = coefficient * G
        self.assertEqual(point.serialize_sec(
            compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.serialize_sec(
            compressed=True), bytes.fromhex(compressed))
        coefficient = 123
        uncompressed = '04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b'
        compressed = '03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5'
        point = coefficient * G
        self.assertEqual(point.serialize_sec(
            compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.serialize_sec(
            compressed=True), bytes.fromhex(compressed))
        coefficient = 42424242
        uncompressed = '04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3'
        compressed = '03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'
        point = coefficient * G
        self.assertEqual(point.serialize_sec(
            compressed=False), bytes.fromhex(uncompressed))
        self.assertEqual(point.serialize_sec(
            compressed=True), bytes.fromhex(compressed))

    def test_address(self):
        secret = 888**3
        mainnet_address = '148dY81A9BmdpMhvYEVznrM45kWN32vSCN'
        testnet_address = 'mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP'
        point = secret * G
        self.assertEqual(
            point.address(compressed=True, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=True, testnet=True), testnet_address)
        secret = 321
        mainnet_address = '1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj'
        testnet_address = 'mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP'
        point = secret * G
        self.assertEqual(
            point.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=False, testnet=True), testnet_address)
        secret = 4242424242
        mainnet_address = '1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb'
        testnet_address = 'mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s'
        point = secret * G
        self.assertEqual(
            point.address(compressed=False, testnet=False), mainnet_address)
        self.assertEqual(
            point.address(compressed=False, testnet=True), testnet_address)


class Signature:
    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def __repr__(self) -> str:
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def serialize_der(self) -> bytes:
        # make 32 bytes and remove all useless prefixed 0x00 data.
        # it can make signature short.
        r_bin = self.r.to_bytes(32, 'big').lstrip(b'\x00')
        s_bin = self.s.to_bytes(32, 'big').lstrip(b'\x00')
        # equal r_bin[0] >= 0x80
        if r_bin[0] & 0x80:
            r_bin = b'\x00' + r_bin
        if s_bin[0] & 0x80:
            s_bin = b'\x00' + s_bin

        r_result = bytes([0x02, len(r_bin)]) + r_bin
        s_result = bytes([0x02, len(s_bin)]) + s_bin
        result = bytes([0x30, len(r_result + s_result)]) + r_result + s_result
        return result

    @classmethod
    def parse_der(cls, signature_bin: bytes) -> 'Signature':
        if signature_bin[0] != 0x30:
            raise ValueError("Signature encoding is not valid")
        sig_len = signature_bin[1]
        if len(signature_bin) != 2 + sig_len:
            raise ValueError("Signature encoding is not valid(Length)")
        if signature_bin[2] != 0x02:
            raise ValueError("Signature encoding is not valid(R)")
        r_len = signature_bin[3]
        r = int.from_bytes(signature_bin[4: 4 + r_len], 'big')
        if signature_bin[4 + r_len] != 0x02:
            raise ValueError("Signature encoding is not valid(S)")
        s_len = signature_bin[5 + r_len]
        s = int.from_bytes(signature_bin[6 + r_len: 6 + r_len + s_len], 'big')
        if len(signature_bin) != 6 + r_len + s_len:
            raise ValueError("Signature encoding is not valid(Length)")
        return cls(r, s)


class SignatureTest(TestCase):
    def test_der(self):
        testcases = (
            (1, 2),
            (randint(0, 2**256), randint(0, 2**255)),
            (randint(0, 2**256), randint(0, 2**255)),
        )
        for r, s in testcases:
            sig = Signature(r, s)
            der = sig.serialize_der()
            sig2 = Signature.parse_der(der)
            self.assertEqual(sig2.r, r)
            self.assertEqual(sig2.s, s)


class PrivateKey:
    def __init__(self, secret: int):
        self.secret = secret
        self.point = secret * G

    def hex(self) -> str:
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z: bytes8) -> 'Signature':
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z: int) -> int:
        k = b'\x00' * 32  # key
        v = b'\x01' * 32  # value
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self, compressed=True, testnet=False) -> str:
        result: bytes
        if testnet:
            result = b'\xef'
        else:
            result = b'\x80'
        secret_bin = self.secret.to_bytes(32, 'big')
        result += secret_bin
        if compressed:
            result += b'\x01'
        return helper.encode_base58_checksum(result)


class PrivateKeyTest(TestCase):

    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

    def test_wif(self):
        pk = PrivateKey(2**256 - 2**199)
        expected = 'L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC'
        self.assertEqual(pk.wif(compressed=True, testnet=False), expected)
        pk = PrivateKey(2**256 - 2**201)
        expected = '93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn'
        self.assertEqual(pk.wif(compressed=False, testnet=True), expected)
        pk = PrivateKey(
            0x0dba685b4511dbd3d368e5c4358a1277de9486447af7b3604a69b8d9d8b7889d)
        expected = '5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty'
        self.assertEqual(pk.wif(compressed=False, testnet=False), expected)
        pk = PrivateKey(
            0x1cca23de92fd1862fb5b76e5f4f50eb082165e5191e116c18ed1a6b24be6a53f)
        expected = 'cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg'
        self.assertEqual(pk.wif(compressed=True, testnet=True), expected)
