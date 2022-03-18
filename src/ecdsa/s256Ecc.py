# BitCoin use secp256k1 and group order which was fixed.
# So, We will call BitCoin's ecdsa 's256 ecc'

from bz2 import compress
import hashlib
import hmac
from src.ecdsa import ecc
from src.helper import helper


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
    def verify(self, z: bytes, sig: 'Signature') -> bool:
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


class PrivateKey:
    def __init__(self, secret: int):
        self.secret = secret
        self.point = secret * G

    def hex(self) -> str:
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z: bytes) -> 'Signature':
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
