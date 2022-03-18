from codecs import StreamReader
from io import BytesIO
import json
from multiprocessing.sharedctypes import Value
from typing import Dict, List
import requests

from src.helper.helper import encode_variant, hash256, int_to_little_endian, little_endian_to_int, read_variant
from src.script.script import Script


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

    def serialize(self):
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

    def fee(self):
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

    def fetch_tx(self, testnet=False) -> Tx:
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
