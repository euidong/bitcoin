from io import BytesIO
from locale import currency
from logging import getLogger
from typing import List, Union
from xmlrpc.client import boolean
from helper.helper import (
    encode_variant, hash160, int_to_little_endian, read_variant, little_endian_to_int)
from src.script.op import (
    OP_CODE_FUNCTIONS, OP_CODE_NAMES, op_equal, op_hash160, op_verify)

LOGGER = getLogger(__name__)


def p2pkh_script(h160: bytes) -> 'Script':
    '''
    Takes a hash160 and returns the p2pkh ScriptPubkey
    (OP_DUP | OP_HASH160 | h160 | OP_EQUALVERIFY | OP_CHECKSIG)
    '''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160: bytes) -> 'Script':
    '''
    Takes a hash160 add returns the p2sh ScriptPubKey
    (OP_HASH160 | h160 | OP_EQUAL)
    '''
    return Script([0xa9, h160, 0x87])


class Script:
    def __init__(self, cmds: List[Union[int, bytes]] = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other: 'Script') -> 'Script':
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s: BytesIO) -> 'Script':
        # get the length of the entire field
        length = read_variant(s)
        # initialize the cmds array
        cmds = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # The next opcode bytes is data to be pushed onto the stack
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            # The next a byte contains the number of bytes to be pushed onto the stack.
            # op_pushdata1
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            # The next two bytes contains the number of bytes to be pushed onto the stack.
            # op_pushdata2
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            # Opcode is stored in cmds. and will be ran runtime.
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self) -> bytes:
        # initialize what we'll send back
        result = b''
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                # otherwise, this is an element.(bytes)
                length = len(cmd)
                # for large lengths, we have to use a pushdata opcode
                if length < 76:
                    result += int_to_little_endian(length, 1)
                elif length < 256:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length < 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def serialize(self) -> bytes:
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        total = len(result)
        return encode_variant(total) + result

    def evaluate(self, z) -> bool:
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            # if cmd type is integer, it is op.
            if type(cmd) == int:
                # operation is function.
                # OP_CODE_FUNCTIONS = Dict[int, function]
                operation = OP_CODE_FUNCTIONS[cmd]
                # this branch is to set parameter for operation
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            # if cmd is bytes, it is element.
            else:
                stack.append(cmd)
                # p2sh logic check
                # this logic only for p2sh
                # now stack have a hash160 data
                if len(cmds) == 3 \
                        and cmds[0] == 0xa9 \
                        and type(cmds[1]) == bytes \
                        and len(cmds[1]) == 20 \
                        and cmds[2] == 0x87:
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    redeem_script = encode_variant(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''
        Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.
        '''
        if len(self.cmds) != 5:
            return False
        if OP_CODE_NAMES[self.cmds[0]] != "OP_DUP":
            return False
        if OP_CODE_NAMES[self.cmds[1]] != "OP_HASH160":
            return False
        if type(self.cmds[2]) != bytes or len(self.cmds[2]) != 20:
            return False
        if OP_CODE_NAMES[self.cmds[3]] != "OP_EQUALVERIFY":
            return False
        if OP_CODE_NAMES[self.cmds[4]] != "OP_CHECKSIG":
            return False
        return True

    def is_p2sh_script_pubkey(self):
        '''
        Returns whether this follows the
        OP_HASH160 <20 bytes hash> OP_EQUAL pattern.
        '''
        if len(self.cmds) != 3:
            return False
        if OP_CODE_NAMES[self.cmds[0]] != 'OP_HASH160':
            return False
        if type(self.cmds[1]) != bytes or len(self.cmds[1]) != 20:
            return False
        if OP_CODE_NAMES[self.cmds[2]] != 'OP_EQUAL':
            return False
        return True
