from network.messages import GenericMessage
from src.helper.helper import bit_field_to_bytes, encode_varint,  int_to_little_endian, murmur3


class BloomFilter:
    def __init__(self, size: int, function_count: int, tweak: int):
        self.size = size
        self.bit_field = [0] * size * 8
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item: bytes) -> None:
        for i in range(self.function_count):
            seed = i * 0xfba4c795 + self.tweak
            h = murmur3(item, seed)
            bit = h % (self.size * 8)
            self.bit_field[bit] = 1

    def filter_bytes(self) -> bytes:
        return bit_field_to_bytes(self.bit_field)

    def filterload(self, flag=1) -> bytes:
        result = encode_varint(self.size)
        result += self.filter_bytes()
        result += int_to_little_endian(self.function_count, 4)
        result += int_to_little_endian(self.tweak, 4)
        result += int_to_little_endian(flag, 1)
        return GenericMessage(b'filterload', result)
