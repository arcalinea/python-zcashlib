# Copyright (C) 2012-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function

import binascii
import struct
import sys
import time

from .script import CScript

from .serialize import *

from .zkproofs import *
from .zkproofs.proof import ZCProof

# Core definitions
COIN = 100000000
MIN_BLOCK_VERSION = 4
MIN_TX_VERSION = 1
MAX_BLOCK_SIZE = 2000000
MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50

def MoneyRange(nValue, params=None):
    global coreparams
    if not params:
      params = coreparams

    return 0 <= nValue <= params.MAX_MONEY

def _py2_x(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h)

def x(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))

def _py2_b2x(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b)

def b2x(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')

def _py2_lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h)[::-1]

def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]

def _py2_b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1])

def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')

if not (sys.version > '3'):
    x = _py2_x
    b2x = _py2_b2x
    lx = _py2_lx
    b2lx = _py2_b2lx

del _py2_x
del _py2_b2x
del _py2_lx
del _py2_b2lx


def str_money_value(value):
    """Convert an integer money value to a fixed point string"""
    r = '%i.%08i' % (value // COIN, value % COIN)
    r = r.rstrip('0')
    if r[-1] == '.':
        r += '0'
    return r


class ValidationError(Exception):
    """Base class for all blockchain validation errors

    Everything that is related to validating the blockchain, blocks,
    transactions, scripts, etc. is derived from this class.
    """

def __make_mutable(cls):
    # For speed we use a class decorator that removes the immutable
    # restrictions directly. In addition the modified behavior of GetHash() and
    # hash() is undone.
    cls.__setattr__ = object.__setattr__
    cls.__delattr__ = object.__delattr__
    cls.GetHash = Serializable.GetHash
    cls.__hash__ = Serializable.__hash__
    return cls


class JSDescription(ImmutableSerializable):
    """A JoinSplit within a transaction"""
    __slots__ = [
        'vpub_old',
        'vpub_new',
        'anchor',
        'nullifiers',
        'commitments',
        'ephemeralKey',
        'ciphertexts',
        'randomSeed',
        'macs',
        'proof',
    ]

    def __init__(self, vpub_old=-1, vpub_new=-1, anchor=b'\x00'*32,
                 nullifiers=(), commitments=(), ephemeralKey=b'\x00'*32,
                 ciphertexts=(), randomSeed=b'\x00'*32, macs=(), proof=ZCProof()):
        object.__setattr__(self, 'vpub_old', int(vpub_old))
        object.__setattr__(self, 'vpub_new', int(vpub_new))
        object.__setattr__(self, 'anchor', anchor)
        object.__setattr__(self, 'nullifiers', tuple(nf for nf in nullifiers))
        object.__setattr__(self, 'commitments', tuple(cm for cm in commitments))
        object.__setattr__(self, 'ephemeralKey', ephemeralKey)
        object.__setattr__(self, 'ciphertexts', tuple(ct for ct in ciphertexts))
        object.__setattr__(self, 'randomSeed', randomSeed)
        object.__setattr__(self, 'macs', tuple(m for m in macs))
        object.__setattr__(self, 'proof', proof)

    @classmethod
    def stream_deserialize(cls, f):
        vpub_old = struct.unpack(b"<q", ser_read(f,8))[0]
        vpub_new = struct.unpack(b"<q", ser_read(f,8))[0]
        anchor = ser_read(f,32)
        nullifiers = [ser_read(f,32) for i in range(ZC_NUM_JS_INPUTS)]
        commitments = [ser_read(f,32) for i in range(ZC_NUM_JS_OUTPUTS)]
        ephemeralKey = ser_read(f,32)
        randomSeed = ser_read(f,32)
        macs = [ser_read(f,32) for i in range(ZC_NUM_JS_INPUTS)]
        proof = ZCProof.stream_deserialize(f)
        ciphertexts = [ser_read(f,ZC_NOTECIPHERTEXT_SIZE) for i in range(ZC_NUM_JS_OUTPUTS)]
        return cls(vpub_old, vpub_new, anchor, nullifiers, commitments,
                   ephemeralKey, ciphertexts, randomSeed, macs, proof)

    def _stream_array(self, f, attr, n, l):
        vals = self.__getattribute__(attr)
        assert len(vals) == n
        for i in range(n):
            assert len(vals[i]) == l
            f.write(vals[i])

    def stream_serialize(self, f):
        f.write(struct.pack(b"<q", self.vpub_old))
        f.write(struct.pack(b"<q", self.vpub_new))
        assert len(self.anchor) == 32
        f.write(self.anchor)
        self._stream_array(f, 'nullifiers', ZC_NUM_JS_INPUTS, 32)
        self._stream_array(f, 'commitments', ZC_NUM_JS_OUTPUTS, 32)
        assert len(self.ephemeralKey) == 32
        f.write(self.ephemeralKey)
        assert len(self.randomSeed) == 32
        f.write(self.randomSeed)
        self._stream_array(f, 'macs', ZC_NUM_JS_INPUTS, 32)
        self.proof.stream_serialize(f)
        self._stream_array(f, 'ciphertexts', ZC_NUM_JS_OUTPUTS, ZC_NOTECIPHERTEXT_SIZE)

    def __repr__(self):
        if self.vpub_old >= 0:
            vpub_old = '%s*COIN' % str_money_value(self.vpub_old)
        else:
            vpub_old = '%d' % self.vpub_old
        if self.vpub_new >= 0:
            vpub_new = '%s*COIN' % str_money_value(self.vpub_new)
        else:
            vpub_new = '%d' % self.vpub_new
        return "JSDescription(%s, %s, %r)" % (vpub_old, vpub_new, b2lx(self.anchor))

    @classmethod
    def from_jsdesc(cls, jsdesc):
        """Create an immutable copy of an existing JSDescription

        If jsdesc is already immutable (jsdesc.__class__ is JSDescription) then it will
        be returned directly.
        """
        if jsdesc.__class__ is JSDescription:
            return jsdesc
        else:
            return cls(
                jsdesc.vpub_old,
                jsdesc.vpub_new,
                jsdesc.anchor,
                jsdesc.nullifiers,
                jsdesc.commitments,
                jsdesc.ephemeralKey,
                jsdesc.ciphertexts,
                jsdesc.randomSeed,
                jsdesc.macs,
                jsdesc.proof
            )

@__make_mutable
class MutableJSDescription(JSDescription):
    """A mutable JSDescription"""
    __slots__ = []

    def __init__(self, vpub_old=-1, vpub_new=-1, anchor=None,
                 nullifiers=None, commitments=None, ephemeralKey=None,
                 ciphertexts=None, randomSeed=None, macs=None, proof=None):
        self.vpub_old = int(vpub_old)
        self.vpub_new = int(vpub_new)
        self.anchor = anchor
        if nullifiers is None:
            nullifiers = []
        self.nullifiers = nullifiers
        if commitments is None:
            commitments = []
        self.commitments = commitments
        self.ephemeralKey = ephemeralKey
        if ciphertexts is None:
            ciphertexts = []
        self.ciphertexts = ciphertexts
        self.randomSeed = randomSeed
        if macs is None:
            macs = []
        self.macs = macs
        if proof is None:
            proof = ZCProof()
        self.proof = proof

    @classmethod
    def from_jsdesc(cls, jsdesc):
        """Create a fully mutable copy of an existing JSDescription"""
        return cls(
            jsdesc.vpub_old,
            jsdesc.vpub_new,
            jsdesc.anchor,
            jsdesc.nullifiers,
            jsdesc.commitments,
            jsdesc.ephemeralKey,
            jsdesc.ciphertexts,
            jsdesc.randomSeed,
            jsdesc.macs,
            jsdesc.proof
        )

class COutPoint(ImmutableSerializable):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__ = ['hash', 'n']

    def __init__(self, hash=b'\x00'*32, n=0xffffffff):
        if not len(hash) == 32:
            raise ValueError('COutPoint: hash must be exactly 32 bytes; got %d bytes' % len(hash))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('COutPoint: n must be in range 0x0 to 0xffffffff; got %x' % n)
        object.__setattr__(self, 'n', n)

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f,32)
        n = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(hash, n)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    def is_null(self):
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self):
        if self.is_null():
            return 'COutPoint()'
        else:
            return 'COutPoint(lx(%r), %i)' % (b2lx(self.hash), self.n)

    def __str__(self):
        return '%s:%i' % (b2lx(self.hash), self.n)

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create an immutable copy of an existing OutPoint

        If outpoint is already immutable (outpoint.__class__ is COutPoint) it is
        returned directly.
        """
        if outpoint.__class__ is COutPoint:
            return outpoint

        else:
            return cls(outpoint.hash, outpoint.n)

@__make_mutable
class CMutableOutPoint(COutPoint):
    """A mutable COutPoint"""
    __slots__ = []

    @classmethod
    def from_outpoint(cls, outpoint):
        """Create a mutable copy of an existing COutPoint"""
        return cls(outpoint.hash, outpoint.n)

class CTxIn(ImmutableSerializable):
    """An input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots__ = ['prevout', 'scriptSig', 'nSequence']

    def __init__(self, prevout=COutPoint(), scriptSig=CScript(), nSequence = 0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        object.__setattr__(self, 'nSequence', nSequence)

        object.__setattr__(self, 'prevout', prevout)
        object.__setattr__(self, 'scriptSig', scriptSig)

    @classmethod
    def stream_deserialize(cls, f):
        prevout = COutPoint.stream_deserialize(f)
        scriptSig = script.CScript(BytesSerializer.stream_deserialize(f))
        nSequence = struct.unpack(b"<I", ser_read(f,4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f):
        COutPoint.stream_serialize(self.prevout, f)
        BytesSerializer.stream_serialize(self.scriptSig, f)
        f.write(struct.pack(b"<I", self.nSequence))

    def is_final(self):
        return (self.nSequence == 0xffffffff)

    def __repr__(self):
        return "CTxIn(%s, %s, 0x%x)" % (repr(self.prevout), repr(self.scriptSig), self.nSequence)

    @classmethod
    def from_txin(cls, txin):
        """Create an immutable copy of an existing TxIn

        If txin is already immutable (txin.__class__ is CTxIn) it is returned
        directly.
        """
        if txin.__class__ is CTxIn:
            return txin

        else:
            return cls(COutPoint.from_outpoint(txin.prevout), txin.scriptSig, txin.nSequence)

@__make_mutable
class CMutableTxIn(CTxIn):
    """A mutable CTxIn"""
    __slots__ = []

    def __init__(self, prevout=None, scriptSig=CScript(), nSequence = 0xffffffff):
        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        self.nSequence = nSequence

        if prevout is None:
            prevout = CMutableOutPoint()
        self.prevout = prevout
        self.scriptSig = scriptSig

    @classmethod
    def from_txin(cls, txin):
        """Create a fully mutable copy of an existing TxIn"""
        prevout = CMutableOutPoint.from_outpoint(txin.prevout)
        return cls(prevout, txin.scriptSig, txin.nSequence)


class CTxOut(ImmutableSerializable):
    """An output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots__ = ['nValue', 'scriptPubKey']

    def __init__(self, nValue=-1, scriptPubKey=script.CScript()):
        object.__setattr__(self, 'nValue', int(nValue))
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)

    @classmethod
    def stream_deserialize(cls, f):
        nValue = struct.unpack(b"<q", ser_read(f,8))[0]
        scriptPubKey = script.CScript(BytesSerializer.stream_deserialize(f))
        return cls(nValue, scriptPubKey)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<q", self.nValue))
        BytesSerializer.stream_serialize(self.scriptPubKey, f)

    def is_valid(self):
        if not MoneyRange(self.nValue):
            return False
        if not self.scriptPubKey.is_valid():
            return False
        return True

    def __repr__(self):
        if self.nValue >= 0:
            return "CTxOut(%s*COIN, %r)" % (str_money_value(self.nValue), self.scriptPubKey)
        else:
            return "CTxOut(%d, %r)" % (self.nValue, self.scriptPubKey)

    @classmethod
    def from_txout(cls, txout):
        """Create an immutable copy of an existing TxOut

        If txout is already immutable (txout.__class__ is CTxOut) then it will
        be returned directly.
        """
        if txout.__class__ is CTxOut:
            return txout

        else:
            return cls(txout.nValue, txout.scriptPubKey)

@__make_mutable
class CMutableTxOut(CTxOut):
    """A mutable CTxOut"""
    __slots__ = []

    @classmethod
    def from_txout(cls, txout):
        """Create a fullly mutable copy of an existing TxOut"""
        return cls(txout.nValue, txout.scriptPubKey)

class CTransaction(ImmutableSerializable):
    """A transaction"""
    __slots__ = ['nVersion', 'vin', 'vout', 'nLockTime', 'vjoinsplit', 'joinSplitPubKey', 'joinSplitSig']

    def __init__(self, vin=(), vout=(), nLockTime=0, nVersion=1, vjoinsplit=(), joinSplitPubKey=b'\x00'*32, joinSplitSig=b'\x00'*64):
        """Create a new transaction

        vin and vout are iterables of transaction inputs and outputs
        respectively. If their contents are not already immutable, immutable
        copies will be made.
        """
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)
        object.__setattr__(self, 'nLockTime', nLockTime)

        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple(CTxIn.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple(CTxOut.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'vjoinsplit', tuple(JSDescription.from_jsdesc(jsdesc) for jsdesc in vjoinsplit))
        object.__setattr__(self, 'joinSplitPubKey', joinSplitPubKey)
        object.__setattr__(self, 'joinSplitSig', joinSplitSig)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        vin = VectorSerializer.stream_deserialize(CTxIn, f)
        vout = VectorSerializer.stream_deserialize(CTxOut, f)
        nLockTime = struct.unpack(b"<I", ser_read(f,4))[0]
        vjoinsplit = ()
        joinSplitPubKey = b'\x00'*32
        joinSplitSig = b'\x00'*64
        if nVersion >= 2:
            vjoinsplit = VectorSerializer.stream_deserialize(JSDescription, f)
            if vjoinsplit:
                joinSplitPubKey = ser_read(f,32)
                joinSplitSig = ser_read(f,64)
        return cls(vin, vout, nLockTime, nVersion, vjoinsplit, joinSplitPubKey, joinSplitSig)

    def stream_serialize(self, f):
        f.write(struct.pack(b"<i", self.nVersion))
        VectorSerializer.stream_serialize(CTxIn, self.vin, f)
        VectorSerializer.stream_serialize(CTxOut, self.vout, f)
        f.write(struct.pack(b"<I", self.nLockTime))
        if self.nVersion >= 2:
            VectorSerializer.stream_serialize(JSDescription, self.vjoinsplit, f)
            if self.vjoinsplit:
                assert len(self.joinSplitPubKey) == 32
                f.write(self.joinSplitPubKey)
                assert len(self.joinSplitSig) == 64
                f.write(self.joinSplitSig)

    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def __repr__(self):
        return "CTransaction(%r, %r, %i, %i)" % (self.vin, self.vout, self.nLockTime, self.nVersion)

    @classmethod
    def from_tx(cls, tx):
        """Create an immutable copy of a pre-existing transaction

        If tx is already immutable (tx.__class__ is CTransaction) then it will
        be returned directly.
        """
        if tx.__class__ is CTransaction:
            return tx

        else:
            return cls(tx.vin, tx.vout, tx.nLockTime, tx.nVersion, tx.vjoinsplit, tx.joinSplitPubKey, tx.joinSplitSig)


@__make_mutable
class CMutableTransaction(CTransaction):
    """A mutable transaction"""
    __slots__ = []

    def __init__(self, vin=None, vout=None, nLockTime=0, nVersion=1, vjoinsplit=None, joinSplitPubKey=None, joinSplitSig=None):
        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)
        self.nLockTime = nLockTime

        if vin is None:
            vin = []
        self.vin = vin

        if vout is None:
            vout = []
        self.vout = vout
        self.nVersion = nVersion

        if vjoinsplit is None:
            vjoinsplit = []
        self.vjoinsplit = vjoinsplit
        self.joinSplitPubKey = joinSplitPubKey
        self.joinSplitSig = joinSplitSig

    @classmethod
    def from_tx(cls, tx):
        """Create a fully mutable copy of a pre-existing transaction"""
        vin = [CMutableTxIn.from_txin(txin) for txin in tx.vin]
        vout = [CMutableTxOut.from_txout(txout) for txout in tx.vout]
        vjoinsplit = [MutableJSDescription.from_jsdesc(jsdesc) for jsdesc in tx.vjoinsplit]

        return cls(vin, vout, tx.nLockTime, tx.nVersion, vjoinsplit, tx.joinSplitPubKey, tx.joinSplitSig)




class CBlockHeader(ImmutableSerializable):
    """A block header"""
    __slots__ = ['nVersion', 'hashPrevBlock', 'hashMerkleRoot', 'hashReserved', 'nTime', 'nBits', 'nNonce', 'nSolution']

    def __init__(self, nVersion=4, hashPrevBlock=b'\x00'*32, hashMerkleRoot=b'\x00'*32,
                 hashReserved=b'\x00'*32, nTime=0, nBits=0, nNonce=b'\x00'*32, nSolution=b'\x00'):
        object.__setattr__(self, 'nVersion', nVersion)
        assert len(hashPrevBlock) == 32
        object.__setattr__(self, 'hashPrevBlock', hashPrevBlock)
        assert len(hashMerkleRoot) == 32
        object.__setattr__(self, 'hashMerkleRoot', hashMerkleRoot)
        assert len(hashReserved) == 32
        object.__setattr__(self, 'hashReserved', hashReserved)
        object.__setattr__(self, 'nTime', nTime)
        object.__setattr__(self, 'nBits', nBits)
        assert len(nNonce) == 32
        object.__setattr__(self, 'nNonce', nNonce)
        object.__setattr__(self, 'nSolution', nSolution)

    @classmethod
    def stream_deserialize(cls, f):
        nVersion = struct.unpack(b"<i", ser_read(f,4))[0]
        hashPrevBlock = ser_read(f,32)
        hashMerkleRoot = ser_read(f,32)
        hashReserved = ser_read(f,32)
        nTime = struct.unpack(b"<I", ser_read(f,4))[0]
        nBits = struct.unpack(b"<I", ser_read(f,4))[0]
        nNonce = ser_read(f,32)
        nSolution = BytesSerializer.stream_deserialize(f)
        return cls(nVersion, hashPrevBlock, hashMerkleRoot, hashReserved, nTime, nBits, nNonce, nSolution)

    def stream_serialize(self, f):
        assert self.nVersion >= MIN_BLOCK_VERSION
        f.write(struct.pack(b"<i", self.nVersion))
        assert len(self.hashPrevBlock) == 32
        f.write(self.hashPrevBlock)
        assert len(self.hashMerkleRoot) == 32
        f.write(self.hashMerkleRoot)
        assert len(self.hashReserved) == 32
        f.write(self.hashReserved)
        f.write(struct.pack(b"<I", self.nTime))
        f.write(struct.pack(b"<I", self.nBits))
        assert len(self.nNonce) == 32
        f.write(self.nNonce)
        BytesSerializer.stream_serialize(self.nSolution, f)

    @staticmethod
    def calc_difficulty(nBits):
        """Calculate difficulty from nBits target"""
        nShift = (nBits >> 24) & 0xff
        dDiff = float(0x0000ffff) / float(nBits & 0x00ffffff)
        while nShift < 29:
            dDiff *= 256.0
            nShift += 1
        while nShift > 29:
            dDiff /= 256.0
            nShift -= 1
        return dDiff
    difficulty = property(lambda self: CBlockHeader.calc_difficulty(self.nBits))

    def __repr__(self):
        return "%s(%i, lx(%s), lx(%s), %s, 0x%08x, lx(%s))" % \
                (self.__class__.__name__, self.nVersion, b2lx(self.hashPrevBlock), b2lx(self.hashMerkleRoot),
                 self.nTime, self.nBits, b2lx(self.nNonce))

class CBlock(CBlockHeader):
    """A block including all transactions in it"""
    __slots__ = ['vtx', 'vMerkleTree']

    @staticmethod
    def build_merkle_tree_from_txids(txids):
        """Build a full CBlock merkle tree from txids

        txids - iterable of txids

        Returns a new merkle tree in deepest first order. The last element is
        the merkle root.

        WARNING! If you're reading this because you're learning about crypto
        and/or designing a new system that will use merkle trees, keep in mind
        that the following merkle tree algorithm has a serious flaw related to
        duplicate txids, resulting in a vulnerability. (CVE-2012-2459) Bitcoin
        has since worked around the flaw, but for new applications you should
        use something different; don't just copy-and-paste this code without
        understanding the problem first.
        """
        merkle_tree = list(txids)

        size = len(txids)
        j = 0
        while size > 1:
            for i in range(0, size, 2):
                i2 = min(i+1, size-1)
                merkle_tree.append(Hash(merkle_tree[j+i] + merkle_tree[j+i2]))

            j += size
            size = (size + 1) // 2

        return merkle_tree

    @staticmethod
    def build_merkle_tree_from_txs(txs):
        """Build a full merkle tree from transactions"""
        txids = [tx.GetHash() for tx in txs]
        return CBlock.build_merkle_tree_from_txids(txids)

    def calc_merkle_root(self):
        """Calculate the merkle root

        The calculated merkle root is not cached; every invocation
        re-calculates it from scratch.
        """
        if not len(self.vtx):
            raise ValueError('Block contains no transactions')
        return self.build_merkle_tree_from_txs(self.vtx)[-1]

    def __init__(self, nVersion=4, hashPrevBlock=b'\x00'*32, hashMerkleRoot=b'\x00'*32,
                 hashReserved=b'\x00'*32, nTime=0, nBits=0, nNonce=b'\x00'*32, nSolution=b'\x00', vtx=()):
        """Create a new block"""
        super(CBlock, self).__init__(nVersion, hashPrevBlock, hashMerkleRoot, hashReserved, nTime, nBits, nNonce, nSolution)

        vMerkleTree = tuple(CBlock.build_merkle_tree_from_txs(vtx))
        object.__setattr__(self, 'vMerkleTree', vMerkleTree)
        object.__setattr__(self, 'vtx', tuple(CTransaction.from_tx(tx) for tx in vtx))

    @classmethod
    def stream_deserialize(cls, f):
        self = super(CBlock, cls).stream_deserialize(f)

        vtx = VectorSerializer.stream_deserialize(CTransaction, f)
        vMerkleTree = tuple(CBlock.build_merkle_tree_from_txs(vtx))
        object.__setattr__(self, 'vMerkleTree', vMerkleTree)
        object.__setattr__(self, 'vtx', tuple(vtx))

        return self

    def stream_serialize(self, f):
        super(CBlock, self).stream_serialize(f)
        VectorSerializer.stream_serialize(CTransaction, self.vtx, f)

    def get_header(self):
        """Return the block header

        Returned header is a new object.
        """
        return CBlockHeader(nVersion=self.nVersion,
                            hashPrevBlock=self.hashPrevBlock,
                            hashMerkleRoot=self.hashMerkleRoot,
                            hashReserved=self.hashReserved,
                            nTime=self.nTime,
                            nBits=self.nBits,
                            nNonce=self.nNonce,
                            nSolution=self.nSolution)

    def GetHash(self):
        """Return the block hash

        Note that this is the hash of the header, not the entire serialized
        block.
        """
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = self.get_header().GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

class CoreChainParams(object):
    """Define consensus-critical parameters of a given instance of the zcash system"""
    MAX_MONEY = None
    GENESIS_BLOCK = None
    PROOF_OF_WORK_LIMIT = None
    SUBSIDY_HALVING_INTERVAL = None
    NAME = None

class CoreMainParams(CoreChainParams):
    MAX_MONEY = 21000000 * COIN
    NAME = 'mainnet'
    GENESIS_BLOCK = CBlock.deserialize(x('040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac4000000000000000000000000000000000000000000000000000000000000000090041358ffff071f5712000000000000000000000000000000000000000000000000000000000000fd4005000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce1570101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 840000
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 13

class CoreTestNetParams(CoreMainParams):
    NAME = 'testnet'
    GENESIS_BLOCK = CBlock.deserialize(x('040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac40000000000000000000000000000000000000000000000000000000000000000a11e1358ffff07200600000000000000000000000000000000000000000000000000000000000000fd400500a6a51259c3f6732481e2d035197218b7a69504461d04335503cd69759b2d02bd2b53a9653f42cb33c608511c953673fa9da76170958115fe92157ad3bb5720d927f18e09459bf5c6072973e143e20f9bdf0584058c96b7c2234c7565f100d5eea083ba5d3dbaff9f0681799a113e7beff4a611d2b49590563109962baa149b628aae869af791f2f70bb041bd7ebfa658570917f6654a142b05e7ec0289a4f46470be7be5f693b90173eaaa6e84907170f32602204f1f4e1c04b1830116ffd0c54f0b1caa9a5698357bd8aa1f5ac8fc93b405265d824ba0e49f69dab5446653927298e6b7bdc61ee86ff31c07bde86331b4e500d42e4e50417e285502684b7966184505b885b42819a88469d1e9cf55072d7f3510f85580db689302eab377e4e11b14a91fdd0df7627efc048934f0aff8e7eb77eb17b3a95de13678004f2512293891d8baf8dde0ef69be520a58bbd6038ce899c9594cf3e30b8c3d9c7ecc832d4c19a6212747b50724e6f70f6451f78fd27b58ce43ca33b1641304a916186cfbe7dbca224f55d08530ba851e4df22baf7ab7078e9cbea46c0798b35a750f54103b0cdd08c81a6505c4932f6bfbd492a9fced31d54e98b6370d4c96600552fcf5b37780ed18c8787d03200963600db297a8f05dfa551321d17b9917edadcda51e274830749d133ad226f8bb6b94f13b4f77e67b35b71f52112ce9ba5da706ad9573584a2570a4ff25d29ab9761a06bdcf2c33638bf9baf2054825037881c14adf3816ba0cbd0fca689aad3ce16f2fe362c98f48134a9221765d939f0b49677d1c2447e56b46859f1810e2cf23e82a53e0d44f34dae932581b3b7f49eaec59af872cf9de757a964f7b33d143a36c270189508fcafe19398e4d2966948164d40556b05b7ff532f66f5d1edc41334ef742f78221dfe0c7ae2275bb3f24c89ae35f00afeea4e6ed187b866b209dc6e83b660593fce7c40e143beb07ac86c56f39e895385924667efe3a3f031938753c7764a2dbeb0a643fd359c46e614873fd0424e435fa7fac083b9a41a9d6bf7e284eee537ea7c50dd239f359941a43dc982745184bf3ee31a8dc850316aa9c6b66d6985acee814373be3458550659e1a06287c3b3b76a185c5cb93e38c1eebcf34ff072894b6430aed8d34122dafd925c46a515cca79b0269c92b301890ca6b0dc8b679cdac0f23318c105de73d7a46d16d2dad988d49c22e9963c117960bdc70ef0db6b091cf09445a516176b7f6d58ec29539166cc8a38bbff387acefffab2ea5faad0e8bb70625716ef0edf61940733c25993ea3de9f0be23d36e7cb8da10505f9dc426cd0e6e5b173ab4fff8c37e1f1fb56d1ea372013d075e0934c6919393cfc21395eea20718fad03542a4162a9ded66c814ad8320b2d7c2da3ecaf206da34c502db2096d1c46699a91dd1c432f019ad434e2c1ce507f91104f66f491fed37b225b8e0b2888c37276cfa0468fc13b8d593fd9a2675f0f5b20b8a15f8fa7558176a530d6865738ddb25d3426dab905221681cf9da0e0200eea5b2eba3ad3a5237d2a391f9074bf1779a2005cee43eec2b058511532635e0fea61664f531ac2b356f40db5c5d275a4cf5c82d468976455af4e3362cc8f71aa95e71d394aff3ead6f7101279f95bcd8a0fedce1d21cb3c9f6dd3b182fce0db5d6712981b651f29178a24119968b14783cafa713bc5f2a65205a42e4ce9dc7ba462bdb1f3e4553afc15f5f39998fdb53e7e231e3e520a46943734a007c2daa1eda9f495791657eefcac5c32833936e568d06187857ed04d7b97167ae207c5c5ae54e528c36016a984235e9c5b2f0718d7b3aa93c7822ccc772580b6599671b3c02ece8a21399abd33cfd3028790133167d0a97e7de53dc8ff0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 5

class CoreRegTestParams(CoreTestNetParams):
    NAME = 'regtest'
    GENESIS_BLOCK = CBlock.deserialize(x('040000000000000000000000000000000000000000000000000000000000000000000000db4d7a85b768123f1dff1d4c4cece70083b2d27e117b4ac2e31d087988a5eac40000000000000000000000000000000000000000000000000000000000000000dae5494d0f0f0f2009000000000000000000000000000000000000000000000000000000000000002401936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b30101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
    SUBSIDY_HALVING_INTERVAL = 150
    PROOF_OF_WORK_LIMIT = 2**256-1 >> 1

"""Master global setting for what core chain params we're using"""
coreparams = CoreMainParams()

def _SelectCoreParams(name):
    """Select the core chain parameters to use

    Don't use this directly, use zcash.SelectParams() instead so both
    consensus-critical and general parameters are set properly.
    """
    global coreparams
    if name == 'mainnet':
        coreparams = CoreMainParams()
    elif name == 'testnet':
        coreparams = CoreTestNetParams()
    elif name == 'regtest':
        coreparams = CoreRegTestParams()
    else:
        raise ValueError('Unknown chain %r' % name)


class CheckTransactionError(ValidationError):
    pass

def CheckTransaction(tx):
    """Basic transaction checks that don't depend on any context.

    Raises CheckTransactionError
    """
    global coreparams

    if tx.nVersion < MIN_TX_VERSION:
        raise CheckTransactionError("CheckTransaction() : version too low")

    if not tx.vin and not tx.vjoinsplit:
        raise CheckTransactionError("CheckTransaction() : vin empty")
    if not tx.vout and not tx.vjoinsplit:
        raise CheckTransactionError("CheckTransaction() : vout empty")

    # Size limits
    if len(tx.serialize()) > MAX_BLOCK_SIZE:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > coreparams.MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : txout.nValue too high")
        nValueOut += txout.nValue
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

    # Ensure that joinsplit values are well-formed
    nValueIn = 0;
    for joinsplit in tx.vjoinsplit:
        if joinsplit.vpub_old < 0:
            raise CheckTransactionError("CheckTransaction() : joinsplit.vpub_old negative")

        if joinsplit.vpub_new < 0:
            raise CheckTransactionError("CheckTransaction() : joinsplit.vpub_new negative")

        if joinsplit.vpub_old > coreparams.MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : joinsplit.vpub_old too high")

        if joinsplit.vpub_new > coreparams.MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : joinsplit.vpub_new too high")

        if joinsplit.vpub_new != 0 and joinsplit.vpub_old != 0:
            raise CheckTransactionError("CheckTransaction() : joinsplit.vpub_new and joinsplit.vpub_old both nonzero")

        nValueOut += joinsplit.vpub_old
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

        # Ensure input values do not exceed MAX_MONEY
        # We have not resolved the txin values at this stage,
        # but we do know what the joinsplits claim to add
        # to the value pool.
        nValueIn += joinsplit.vpub_new
        if not MoneyRange(joinsplit.vpub_new) or not MoneyRange(nValueIn):
            raise CheckTransactionError("CheckTransaction() : txin total out of range")

    # Check for duplicate inputs
    vin_outpoints = set()
    for txin in tx.vin:
        if txin.prevout in vin_outpoints:
            raise CheckTransactionError("CheckTransaction() : duplicate inputs")
        vin_outpoints.add(txin.prevout)

    # Check for duplicate joinsplit nullifiers in this transaction
    vjoinsplit_nullifiers = set()
    for joinsplit in tx.vjoinsplit:
        for nf in joinsplit.nullifiers:
            if nf in vjoinsplit_nullifiers:
                raise CheckTransactionError("CheckTransaction() : duplicate nullifiers")
            vjoinsplit_nullifiers.add(nf)

    if tx.is_coinbase():
        # There should be no joinsplits in a coinbase transaction
        if tx.vjoinsplit:
            raise CheckTransactionError("CheckTransaction() : coinbase has joinsplits")

        if not (2 <= len(tx.vin[0].scriptSig) <= 100):
            raise CheckTransactionError("CheckTransaction() : coinbase script size")

    else:
        for txin in tx.vin:
            if txin.prevout.is_null():
                raise CheckTransactionError("CheckTransaction() : prevout is null")

        if tx.vjoinsplit:
            # TODO: Check JoinSplit signature
            pass





class CheckBlockHeaderError(ValidationError):
    pass

class CheckProofOfWorkError(CheckBlockHeaderError):
    pass

def CheckProofOfWork(hash, nBits):
    """Check a proof-of-work

    Raises CheckProofOfWorkError
    """
    target = uint256_from_compact(nBits)

    # Check range
    if not (0 < target <= coreparams.PROOF_OF_WORK_LIMIT):
        raise CheckProofOfWorkError("CheckProofOfWork() : nBits below minimum work")

    # Check proof of work matches claimed amount
    hash = uint256_from_str(hash)
    if hash > target:
        raise CheckProofOfWorkError("CheckProofOfWork() : hash doesn't match nBits")


def CheckBlockHeader(block_header, fCheckPoW = True, cur_time=None):
    """Context independent CBlockHeader checks.

    fCheckPoW - Check proof-of-work.

    cur_time  - Current time. Defaults to time.time()

    Raises CBlockHeaderError if block header is invalid.
    """
    if cur_time is None:
        cur_time = time.time()

    # Check proof-of-work matches claimed amount
    if fCheckPoW:
        CheckProofOfWork(block_header.GetHash(), block_header.nBits)

    # Check timestamp
    if block_header.nTime > cur_time + 2 * 60 * 60:
        raise CheckBlockHeaderError("CheckBlockHeader() : block timestamp too far in the future")


class CheckBlockError(CheckBlockHeaderError):
    pass

def GetLegacySigOpCount(tx):
    nSigOps = 0
    for txin in tx.vin:
        nSigOps += txin.scriptSig.GetSigOpCount(False)
    for txout in tx.vout:
        nSigOps += txout.scriptPubKey.GetSigOpCount(False)
    return nSigOps


def CheckBlock(block, fCheckPoW = True, fCheckMerkleRoot = True, cur_time=None):
    """Context independent CBlock checks.

    CheckBlockHeader() is called first, which may raise a CheckBlockHeader
    exception, followed the block tests. CheckTransaction() is called for every
    transaction.

    fCheckPoW        - Check proof-of-work.

    fCheckMerkleRoot - Check merkle root matches transactions.

    cur_time         - Current time. Defaults to time.time()
    """

    # Block header checks
    CheckBlockHeader(block.get_header(), fCheckPoW=fCheckPoW, cur_time=cur_time)

    # Size limits
    if not block.vtx:
        raise CheckBlockError("CheckBlock() : vtx empty")
    if len(block.serialize()) > MAX_BLOCK_SIZE:
        raise CheckBlockError("CheckBlock() : block larger than MAX_BLOCK_SIZE")

    # First transaction must be coinbase
    if not block.vtx[0].is_coinbase():
        raise CheckBlockError("CheckBlock() : first tx is not coinbase")

    # Check rest of transactions. Note how we do things "all at once", which
    # could potentially be a consensus failure if there was some obscure bug.

    # For unique txid uniqueness testing. If coinbase tx is included twice
    # it'll be caught by the "more than one coinbase" test.
    unique_txids = set()
    nSigOps = 0
    for tx in block.vtx[1:]:
        if tx.is_coinbase():
            raise CheckBlockError("CheckBlock() : more than one coinbase")

        CheckTransaction(tx)

        txid = tx.GetHash()
        if txid in unique_txids:
            raise CheckBlockError("CheckBlock() : duplicate transaction")
        unique_txids.add(txid)

        nSigOps += GetLegacySigOpCount(tx)
        if nSigOps > MAX_BLOCK_SIGOPS:
            raise CheckBlockError("CheckBlock() : out-of-bounds SigOpCount")

    # Check merkle root
    if fCheckMerkleRoot and block.hashMerkleRoot != block.calc_merkle_root():
        raise CheckBlockError("CheckBlock() : hashMerkleRoot mismatch")

__all__ = (
        'Hash',
        'Hash160',
        'COIN',
        'MAX_BLOCK_SIZE',
        'MAX_BLOCK_SIGOPS',
        'MoneyRange',
        'x',
        'b2x',
        'lx',
        'b2lx',
        'str_money_value',
        'ValidationError',
        'COutPoint',
        'CMutableOutPoint',
        'CTxIn',
        'CMutableTxIn',
        'CTxOut',
        'CMutableTxOut',
        'CTransaction',
        'CMutableTransaction',
        'CBlockHeader',
        'CBlock',
        'CoreChainParams',
        'CoreMainParams',
        'CoreTestNetParams',
        'CoreRegTestParams',
        'CheckTransactionError',
        'CheckTransaction',
        'CheckBlockHeaderError',
        'CheckProofOfWorkError',
        'CheckProofOfWork',
        'CheckBlockHeader',
        'CheckBlockError',
        'GetLegacySigOpCount',
        'CheckBlock',
)
