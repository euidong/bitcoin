from unittest import TestCase
from io import BytesIO
from src.helper.helper import (
    encode_variant, little_endian_to_int, int_to_little_endian, read_variant)


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

    def test_variant(self):
        ints = (0x00, 0x01, 0xfe, 0xfff, 0x10000,
                0x100000000, 0xffffffffffffffff)
        for i in ints:
            e = encode_variant(i)
            self.assertEqual(read_variant(BytesIO(e)), i)
        with self.assertRaises(ValueError):
            encode_variant(0x10000000000000000)
