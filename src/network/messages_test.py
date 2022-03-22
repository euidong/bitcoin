from io import BytesIO
from unittest import TestCase

from src.block.block import Block
from src.network.messages import (
    VersionMessage, GetHeadersMessage, HeadersMessage)


class VersionMessageTest(TestCase):
    def test_serialize(self):
        v = VersionMessage(timestamp=0, nonce=b'\x00' * 8)
        self.assertEqual(v.serialize().hex(
        ), '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000')

    def test_parse(self):
        vm_s = '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000'
        vm = VersionMessage.parse(BytesIO(bytes.fromhex(vm_s)))
        target_vm = VersionMessage(timestamp=0, nonce=b'\x00' * 8)

        self.assertEqual(vm.command, target_vm.command)

        self.assertEqual(vm.version, target_vm.version)
        self.assertEqual(vm.services, target_vm.services)
        self.assertEqual(vm.timestamp, target_vm.timestamp)

        self.assertEqual(vm.receiver_services, target_vm.receiver_services)
        self.assertEqual(vm.receiver_ip, target_vm.receiver_ip)
        self.assertEqual(vm.receiver_port, target_vm.receiver_port)

        self.assertEqual(vm.sender_services, target_vm.sender_services)
        self.assertEqual(vm.sender_ip, target_vm.sender_ip)
        self.assertEqual(vm.sender_port, target_vm.sender_port)

        self.assertEqual(vm.nonce, target_vm.nonce)
        self.assertEqual(vm.user_agent, target_vm.user_agent)
        self.assertEqual(vm.latest_block, target_vm.latest_block)
        self.assertEqual(vm.relay, target_vm.relay)


class GetHeadersMessageTest(TestCase):
    def test_serialize(self):
        block_hex = '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'
        gh = GetHeadersMessage(start_block=bytes.fromhex(block_hex))
        self.assertEqual(gh.serialize().hex(
        ), '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000')

    def test_parse(self):
        ghm_s = '7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        ghm = GetHeadersMessage.parse(BytesIO(bytes.fromhex(ghm_s)))

        target_ghm = GetHeadersMessage(start_block=bytes.fromhex(
            '0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3'))

        self.assertEqual(ghm.command, target_ghm.command)
        self.assertEqual(ghm.version, target_ghm.version)
        self.assertEqual(ghm.num_hashes, target_ghm.num_hashes)
        self.assertEqual(ghm.start_block, target_ghm.start_block)
        self.assertEqual(ghm.end_block, target_ghm.end_block)


class HeadersMessageTest(TestCase):
    def test_serialize(self):
        hm = HeadersMessage(blocks=[
            Block.parse(BytesIO(bytes.fromhex(
                '00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670'))),
            Block.parse(BytesIO(bytes.fromhex(
                '0000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade092046')))
        ])
        self.assertEqual(hm.serialize().hex(), '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600')

    def test_parse(self):
        hex_msg = '0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600'
        stream = BytesIO(bytes.fromhex(hex_msg))
        headers = HeadersMessage.parse(stream)
        self.assertEqual(len(headers.blocks), 2)
        for b in headers.blocks:
            self.assertEqual(b.__class__, Block)
