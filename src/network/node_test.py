from unittest import TestCase

from src.network.node import SimpleNode


class SimpleNodeTest(TestCase):
    def test_handshake(self):
        node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)
        node.handshake()
