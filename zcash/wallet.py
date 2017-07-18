# Copyright (C) 2012-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Wallet-related functionality

Includes things like representing addresses and converting them to/from
scriptPubKeys; currently there is no actual wallet support implemented.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys

_bord = ord
if sys.version > '3':
    _bord = lambda x: x

import zcash
# import bitcoin.wallet
import zcash.base58
import zcash.core
import zcash.core.key
import zcash.core.script as script

'''class CBitcoinAddressError(zcash.base58.Base58Error):
    """Raised when an invalid zcash address is encountered"""
    raise NotImplementedError

class CZCPaymentAddress(zcash.base58.Base58Error):
    """A zcash shielded address"""
    raise NotImplementedError

class CZCSpendingKey(zcash.base58.Base58Error):
    """A zcash spending key"""
    raise NotImplementedError
'''
class CBitcoinAddress(zcash.base58.CBase58Data):
    """A zcash transparent address"""
    @classmethod
    def from_bytes(cls, data, nVersion):
        self = super(CBitcoinAddress, cls).from_bytes(data, nVersion)
        if nVersion == zcash.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            self.__class__ = P2SHBitcoinAddress

        elif nVersion == zcash.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            self.__class__ = P2PKHBitcoinAddress

        else:
           raise CBitcoinAddressError('Version {0} not a recognized zcash Address'.format(nVersion))

        return self

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a CBitcoinAddress

        Returns a CBitcoinAddress subclass, either P2SHBitcoinAddress or
        P2PKHBitcoinAddress. If the scriptPubKey is not recognized
        CBitcoinAddressError will be raised.
        """
        try:
            return P2SHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        try:
            return P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)
        except CBitcoinAddressError:
            pass

        raise CBitcoinAddressError('scriptPubKey not a valid address')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        raise NotImplementedError

class P2SHBitcoinAddress(CBitcoinAddress):
    @classmethod
    def from_bytes(cls, data, nVersion=None):
        if nVersion is None:
            nVersion = zcash.params.BASE58_PREFIXES['SCRIPT_ADDR']

        elif nVersion != zcash.params.BASE58_PREFIXES['SCRIPT_ADDR']:
            raise ValueError('nVersion incorrect for P2SH address: got %d; expected %d' % \
                                (nVersion, zcash.params.BASE58_PREFIXES['SCRIPT_ADDR']))

        return super(P2SHBitcoinAddress, cls).from_bytes(data, nVersion)

    @classmethod
    def from_redeemScript(cls, redeemScript):
        """Convert a redeemScript to a P2SH address

        Convenience function: equivalent to P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey):
        """Convert a scriptPubKey to a P2SH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2sh():
            # are there 23 bytes here for zcash?
            return cls.from_bytes(scriptPubKey[2:22], zcash.params.BASE58_PREFIXES['SCRIPT_ADDR'])

        else:
            raise CBitcoinAddressError('not a P2SH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.nVersion == zcash.params.BASE58_PREFIXES['SCRIPT_ADDR']
        return script.CScript([script.OP_HASH160, self, script.OP_EQUAL])

class P2PKHBitcoinAddress(CBitcoinAddress):
    # convert a bitcoin P2PKH address to the zcash one with same public key hash
    @classmethod
    def from_bitcoin_address(cls, bitcoinAddress):
        btcPubKeyHash = bitcoin.wallet.P2PKHBitcoinAddress(bitcoinAddress).to_bytes()
        return P2PKHBitcoinAddress.from_bytes(btcPubKeyHash)

    @classmethod
    def from_privkey(cls, privkey):
        return P2PKHBitcoinAddress.from_pubkey(privkey.pub)


    @classmethod
    def from_bytes(cls, data, nVersion=None):
        if nVersion is None:
            nVersion = zcash.params.BASE58_PREFIXES['PUBKEY_ADDR']

        elif nVersion != zcash.params.BASE58_PREFIXES['PUBKEY_ADDR']:
            print("nversion:",nVersion)
            raise ValueError('nVersion incorrect for P2PKH address: got %d; expected %d' % \
                                (nVersion, zcash.params.BASE58_PREFIXES['PUBKEY_ADDR']))

        return super(P2PKHBitcoinAddress, cls).from_bytes(data, nVersion)

    @classmethod
    def from_pubkey(cls, pubkey, accept_invalid=False):
        """Create a P2PKH zcash address from a pubkey

        Raises CBitcoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance; CECKey instances are not accepted.
        """
        if not isinstance(pubkey, bytes):
            raise TypeError('pubkey must be bytes instance; got %r' % pubkey.__class__)

        if not accept_invalid:
            if not isinstance(pubkey, zcash.core.key.CPubKey):
                pubkey = zcash.core.key.CPubKey(pubkey)
            if not pubkey.is_fullyvalid:
                raise CBitcoinAddressError('invalid pubkey')

        pubkey_hash = zcash.core.Hash160(pubkey)
        return P2PKHBitcoinAddress.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls, scriptPubKey, accept_non_canonical_pushdata=True, accept_bare_checksig=True):
        """Convert a scriptPubKey to a P2PKH address

        Raises CBitcoinAddressError if the scriptPubKey isn't of the correct
        form.

        accept_non_canonical_pushdata - Allow non-canonical pushes (default True)

        accept_bare_checksig          - Treat bare-checksig as P2PKH scriptPubKeys (default True)
        """
        if accept_non_canonical_pushdata:
            # Canonicalize script pushes
            scriptPubKey = script.CScript(scriptPubKey) # in case it's not a CScript instance yet

            try:
                scriptPubKey = script.CScript(tuple(scriptPubKey)) # canonicalize
            except zcash.core.script.CScriptInvalidError:
                raise CBitcoinAddressError('not a P2PKH scriptPubKey: script is invalid')

        if (len(scriptPubKey) == 25
                and _bord(scriptPubKey[0])  == script.OP_DUP
                and _bord(scriptPubKey[1])  == script.OP_HASH160
                and _bord(scriptPubKey[2])  == 0x14
                and _bord(scriptPubKey[23]) == script.OP_EQUALVERIFY
                and _bord(scriptPubKey[24]) == script.OP_CHECKSIG):
            return cls.from_bytes(scriptPubKey[3:23], zcash.params.BASE58_PREFIXES['PUBKEY_ADDR'])

        elif accept_bare_checksig:
            pubkey = None

            # We can operate on the raw bytes directly because we've
            # canonicalized everything above.
            if (len(scriptPubKey) == 35 # compressed
                  and _bord(scriptPubKey[0])  == 0x21
                  and _bord(scriptPubKey[34]) == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:34]

            elif (len(scriptPubKey) == 67 # uncompressed
                    and _bord(scriptPubKey[0]) == 0x41
                    and _bord(scriptPubKey[66]) == script.OP_CHECKSIG):

                pubkey = scriptPubKey[1:65]

            if pubkey is not None:
                return cls.from_pubkey(pubkey, accept_invalid=True)

        raise CBitcoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self):
        """Convert an address to a scriptPubKey"""
        assert self.nVersion == zcash.params.BASE58_PREFIXES['PUBKEY_ADDR']
        return script.CScript([script.OP_DUP, script.OP_HASH160, self, script.OP_EQUALVERIFY, script.OP_CHECKSIG])

class CKey(object):
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key

    is_compressed - True if compressed

    """
    def __init__(self, secret, compressed=True):
        self._cec_key = zcash.core.key.CECKey()
        self._cec_key.set_secretbytes(secret)
        self._cec_key.set_compressed(compressed)

        self.pub = zcash.core.key.CPubKey(self._cec_key.get_pubkey(), self._cec_key)

    @property
    def is_compressed(self):
        return self.pub.is_compressed

    def sign(self, hash):
        return self._cec_key.sign(hash)

    def sign_compact(self, hash):
        return self._cec_key.sign_compact(hash)

class CBitcoinSecretError(zcash.base58.Base58Error):
    pass

class CBitcoinSecret(zcash.base58.CBase58Data, CKey):
    """A base58-encoded secret key"""

    @classmethod
    def from_secret_bytes(cls, secret, compressed=True):
        """Create a secret key from a 32-byte secret"""
        self = cls.from_bytes(secret + (b'\x01' if compressed else b''),
                              zcash.params.BASE58_PREFIXES['SECRET_KEY'])
        self.__init__(None)
        return self

    def __init__(self, s):
        if self.nVersion != zcash.params.BASE58_PREFIXES['SECRET_KEY']:
            raise CBitcoinSecretError('Not a base58-encoded secret key: got nVersion={0}; expected nVersion={1}'.format(self.nVersion, zcash.params.BASE58_PREFIXES['SECRET_KEY']))

        CKey.__init__(self, self[0:32], len(self) > 32 and _bord(self[32]) == 1)


__all__ = (
        'CBitcoinAddressError',
        'CBitcoinAddress',
        'P2SHBitcoinAddress',
        'P2PKHBitcoinAddress',
        'CKey',
        'CBitcoinSecretError',
        'CBitcoinSecret',
)
