import math
from typing import List

from helper.helper import merkle_parent, merkle_root


class MerkleTree:
    '''
    node looks like that.
    [
        [None]
        [None, None]
        [None, None, None, None]
    ]
    '''

    def __init__(self, total: int):
        self.total = total
        self.max_depth = math.ceil(math.log(self.total, 2))
        self.nodes = []
        for depth in range(self.max_depth + 1):
            num_items = math.ceil(self.total / 2 ** (self.max_depth - depth))
            level_hashes = [None] * num_items
            self.nodes.append(level_hashes)
        self.current_depth = 0
        self.current_index = 0

    def __repr__(self) -> str:
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for index, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = '{}...'.format(h.hex()[:8])
                if depth == self.current_depth and index == self.current_index:
                    items.append('*{}*'.format(short[:2]))
                else:
                    items.append('{}'.format(short))
            result.append(', '.join(items))
        return '\n'.join(result)

    def up(self) -> None:
        if self.is_root():
            raise RuntimeError("can't move lower 0")
        self.current_depth -= 1
        self.current_index //= 2

    def left(self) -> None:
        if self.is_leaf():
            raise RuntimeError("cant't move upper {}".format(self.max_depth))
        self.current_depth += 1
        self.current_index *= 2

    def right(self) -> None:
        if self.is_leaf():
            raise RuntimeError("cant't move upper {}".format(self.max_depth))
        self.current_depth += 1
        self.current_index = self.current_index * 2 + 1

    def root(self) -> bytes:
        return self.nodes[0][0]

    def set_current_node(self, value: bytes) -> None:
        self.nodes[self.current_depth][self.current_index] = value

    def get_current_node(self) -> bytes:
        return self.nodes[self.current_depth][self.current_index]

    def get_left_node(self) -> bytes:
        if self.is_leaf():
            raise RuntimeError("can't get leaf Nodes left Node")
        return self.nodes[self.current_depth + 1][self.current_index * 2]

    def get_right_node(self) -> bytes:
        if self.is_leaf():
            raise RuntimeError("can't get leaf Nodes right Node")
        return self.nodes[self.current_depth + 1][self.current_index * 2 + 1]

    def is_root(self) -> bool:
        return self.current_depth == 0

    def is_leaf(self) -> bool:
        return self.max_depth == self.current_depth

    def left_exists(self) -> bool:
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2

    def right_exists(self) -> bool:
        return len(self.nodes[self.current_depth + 1]) > self.current_index * 2 + 1

    def populate_tree(self, flag_bits: List[int], hashes: List[bytes]) -> bytes:
        flag = flag_bits.pop(0)
        if self.is_leaf() or flag == 0:
            self.set_current_node(hashes.pop(0))
            value = self.get_current_node()
            return value

        if self.left_exists():
            left = self.get_left_node()
            if left is None:
                self.left()
                left = self.populate_tree(flag_bits, hashes)
                self.up()
        else:
            self.set_current_node(hashes.pop(0))
            value = self.get_current_node()
            return value
        if self.right_exists():
            right = self.get_right_node()
            if right is None:
                self.right()
                right = self.populate_tree(flag_bits, hashes)
                self.up()
        else:
            right = left

        value = merkle_parent(left, right)
        self.set_current_node(value)
        return value
