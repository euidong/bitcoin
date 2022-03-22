import socket
from typing import List

from src.network.envelope import Envelope
from src.network.messages import Message, PingMessage, PongMessage, VerAckMessage, VersionMessage


class SimpleNode:
    def __init__(self, host: int, port: int = None, testnet: bool = False, logging: bool = False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        else:
            self.port = port
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb', None)

    def handshake(self):
        '''
        Do a handshake with the other node.
        Handshake is sending a version message and getting a verack back.
        '''
        self.send(VersionMessage())
        verack_received = False
        version_received = False
        while not (verack_received and version_received):
            message = self.wait_for(VerAckMessage, VersionMessage)
            if message.command == VerAckMessage.command:
                verack_received = True
            else:
                version_received = True

    def send(self, message: Message) -> None:
        '''Send a message to the connected node.'''
        envelope = Envelope(
            message.command,
            message.serialize(),
            testnet=self.testnet
        )
        if self.logging:
            print('sending: {}'.format(envelope))
        self.socket.sendall(envelope.serialize())

    def read(self) -> Envelope:
        '''Read a message from the socket.'''
        envelope = Envelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print('receiving: {}'.format(envelope))
        return envelope

    def wait_for(self, *message_classes: Message) -> Message:
        '''
        Wait for one of the messages in the list.
        And Returns this message.
        '''
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(envelope.stream())
