from codecs import StreamReader
from io import BytesIO
import json
from multiprocessing.sharedctypes import Value
from typing import Dict, List
import requests
from ecdsa.s256Ecc import B, PrivateKey, Signature

from src.helper.helper import SIGHASH_ALL, encode_variant, hash256, int_to_little_endian, little_endian_to_int, read_variant
from src.script.script import Script


class TxIn:
    '''
    prev_tx : previous transaction's hased serialization.
    prev_index: previous transaction's output index.
    '''

    def __init__(self, prev_tx: bytes, prev_index: int, script_sig: Script = None, sequence: int = 0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index
        )

    @classmethod
    def parse(cls, s: BytesIO) -> 'TxIn':
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        result = self.prev_tx[::-1]  # reverse previous transaction bytes
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False) -> 'Tx':
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False) -> int:
        '''
        Get the output value by looking up the tx hash.
        Returns the amount in satoshi
        '''
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False) -> Script:
        '''
        Get the ScriptPubKey by looking up the tx hash.
        Returns a script object
        '''
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    '''
    amount is 8bytes. The unit of this is satoshi.(1 satoshi = 10^-8 bitcoin)
    So, maximum amount is 21 million bitcoins.
    '''

    def __init__(self, amount: int, script_pubkey: Script):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s: BytesIO) -> 'TxOut':
        amount = little_endian_to_int(s.read(8))
        script_key = Script.parse(s)
        return cls(amount, script_key)

    def serialize(self) -> bytes:
        '''Return the bytes serialization of the transaction outpute'''
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


class Tx:
    def __init__(
        self, version: int,
        tx_ins: List['TxIn'], tx_outs: List['TxOut'],
        locktime: int, testnet=False
    ):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self) -> str:
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime
        )

    def id(self) -> str:
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()

    def hash(self) -> bytes:
        '''Binary hash of the legacy serialization(32bytes)'''
        return hash256(self.serialize())[::-1]  # reverse endian

    @classmethod
    def parse(cls, s: StreamReader, testnet=False) -> 'Tx':
        '''
        Takes a byte stream and parses the transaction at the start
        return a Tx object
        '''
        version = little_endian_to_int(s.read(4))
        tx_in_len = read_variant(s)
        if tx_in_len == 0:
            raise ValueError('Tx need at least one input')
        tx_ins = []
        for _ in range(tx_in_len):
            tx_ins.append(TxIn.parse(s))
        tx_out_len = read_variant(s)
        if tx_out_len == 0:
            raise ValueError('Tx need at least one output')
        tx_outs = []
        for _ in range(tx_out_len):
            tx_outs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version=version, tx_ins=tx_ins, tx_outs=tx_outs, locktime=locktime)

    def serialize(self) -> bytes:
        '''Returns the byte serialization of the transaction'''
        result = int_to_little_endian(self.version, 4)
        result += encode_variant(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_variant(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self) -> int:
        '''Returns the fee of this transaction in satoshi'''
        # get all inputs tx
        in_amount = 0
        for tx_in in self.tx_ins:
            in_amount += tx_in.value()
        out_amount = 0
        for tx_out in self.tx_outs:
            out_amount += tx_out.amount
        if in_amount < out_amount:
            raise SyntaxError(
                "Input amount is lower than Output amount, It'll make a new bitcoin.")
        return in_amount - out_amount

    def sig_hash(self, input_index: int, redeem_script=None) -> int:
        '''
        Returns the integer representation of the hash that needs to get
        signed for index input_index
        '''
        # start the serialization with version
        # use int_to_little_endian in 4 bytes
        result = int_to_little_endian(self.version, 4)

        # add how many inputs there are using encode_varint
        result += encode_variant(len(self.tx_ins))

        # loop through each input using enumerate, so we have the input index
        # if the input index is the one we're signing
        # the previous tx's ScriptPubkey is the ScriptSig or Redeem_script
        # Otherwise, the ScriptSig is empty
        # add the serialization of the input with the ScriptSig we want
        for idx, tx_in in enumerate(self.tx_ins):
            if idx == input_index:
                if redeem_script:
                    script_sig = redeem_script
                else:
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None
            result += TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        # add how many outputs there are using encode_varint
        result += encode_variant(len(self.tx_outs))
        # add the serialization of each output
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        # add the locktime using int_to_little_endian in 4 bytes
        result += int_to_little_endian(self.locktime, 4)
        # add SIGHASH_ALL using int_to_little_endian in 4 bytes
        result += int_to_little_endian(SIGHASH_ALL, 4)
        # hash256 the serialization
        z = hash256(result)
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(z, 'big')

    def verify_input(self, input_index: int) -> bool:
        '''Returns whether the input has a valid signature'''
        # get the relevant input
        tx_in = self.tx_ins[input_index]
        # grab the previous ScriptPubKey
        script_pubkey = tx_in.script_pubkey(self.testnet)
        if script_pubkey.is_p2sh_script_pubkey():
            cmd = tx_in.script_sig.cmds[-1]
            raw_redeem = encode_variant(len(cmd)) + cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
        else:
            redeem_script = None
        # get the signature hash (z)
        z = self.sig_hash(input_index, redeem_script)
        # combine the current ScriptSig and the previous ScriptPubKey
        script = tx_in.script_sig + script_pubkey
        # evaluate the combined script
        return script.evaluate(z)

    def verify(self) -> bool:
        '''Verify this transaction'''
        # 1. check unspent (query UTXO)

        # 2. check fee
        if self.fee() < 0:
            return False
        # 3. check validation of input.
        for idx in range(len(self.tx_ins)):
            if not self.verify_input(idx):
                return False
        return True

    def sign_input(self, input_index: int, private_key: PrivateKey) -> Signature:
        # get the signature hash (z)
        z = self.sig_hash(input_index)
        # get der signature of z from private key
        der = private_key.sign(z).serialize_der()
        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # calculate the sec
        sec = private_key.point.serialize_sec()
        # initialize a new script with [sig, sec] as the cmds
        script = Script([sig, sec])
        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script
        # return whether sig is valid using self.verify_input
        return self.verify_input(input_index)

    def is_coinbase(self) -> bool:
        if len(self.tx_ins) != 1:
            return False
        if self.tx_ins[0].prev_tx != int.to_bytes(0, 32, 'little'):
            return False
        if self.tx_ins[0].prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self) -> int:
        '''
        Returns the height of the block this coinbase transaction is in 
        Returns None if this transaction is not a coinbase transaction
        '''
        if not self.is_coinbase():
            return None
        return little_endian_to_int(self.tx_ins[0].script_sig.cmds[0])


class TxFetcher:
    cache: Dict[str, Tx] = {}

    @classmethod
    def get_url(cls, testnet=False) -> str:
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id: str, testnet=False, fresh=False) -> Tx:
        '''
        get Transaction with tx_id, if already fetched then we can use cached data.
        fresh: ignore cached data, and fetch.
        '''
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(
                    'unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError(
                    'not the same id: {}(response) vs {}(request)'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        # TODO: check is good or not, now i think that have a problem.
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename: str) -> None:
        data = open(filename, 'r').read()
        disk_cache = json.loads(data)
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cacahe(cls, filename: str) -> None:
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)
