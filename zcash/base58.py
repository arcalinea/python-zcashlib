# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Base58 encoding and decoding"""

from __future__ import absolute_import, division, print_function, unicode_literals


import sys
_bchr = chr
_bord = ord
if sys.version > '3':
    long = int
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

import binascii

import zcash.core

B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    """Raised on generic invalid base58 data, such as bad characters.

    Checksum failures raise Base58ChecksumError specifically.
    """
    pass

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res

def decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in B58_DIGITS:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = B58_DIGITS.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]: pad += 1
        else: break
    return b'\x00' * pad + res


class Base58ChecksumError(Base58Error):
    """Raised on Base58 checksum errors"""
    pass

class CBase58Data(bytes):
    """Base58-encoded data

    Includes a version and checksum.
    """
    def __new__(cls, s):
        k = decode(s)
        """ In Zcash private keys have one byte version numbers (same as bitcoin) but other base58 encoded objects have two bytes"""
        """ That's why there is an if here compared to the bitcoin original version """
        """ This condition is a bit sloppy incase 128 will ever be used as a prefix of something else on mainnet """
        if (bytes(k[0:1]) == b'\xef' or  bytes(k[0:1])== b'\x80'):
            verbyte, data, check0 = k[0:1], k[1:-4], k[-4:]
            check1 = zcash.core.Hash(verbyte + data)[:4]
            if check0 != check1:
                raise Base58ChecksumError('Checksum mismatch: expected %r, calculated %r' % (check0, check1))
            return cls.from_bytes(data, _bord(verbyte[0]))
        else:
            verbyte, data, check0 = k[0:2], k[2:-4], k[-4:]
            check1 = zcash.core.Hash(verbyte + data)[:4]
            if check0 != check1:
                raise Base58ChecksumError('Checksum mismatch: expected %r, calculated %r' % (check0, check1))
            return cls.from_bytes(data, verbyte[0:2])

    def __init__(self, s):
        """Initialize from base58-encoded string

        Note: subclasses put your initialization routines here, but ignore the
        argument - that's handled by __new__(), and .from_bytes() will call
        __init__() with None in place of the string.
        """

    @classmethod
    def from_bytes(cls, data, nVersion):
        """Instantiate from data and nVersion"""
        if type(nVersion) == int:
            if not (0 <= nVersion <= 8000):
                raise ValueError('nVersion must be in range 0 to 8000 inclusive; got %d' % nVersion)
        self = bytes.__new__(cls, data)
        self.nVersion = nVersion

        return self

    def to_bytes(self):
        """Convert to bytes instance

        Note that it's the data represented that is converted; the checkum and
        nVersion is not included.
        """
        return b'' + self

    def __str__(self):
        """Convert to string"""
        # print("nversion type", type(self.nVersion)," val", self.nVersion)
        if type(self.nVersion) == int:
            #print("here in int")
            vs = _bchr(self.nVersion) + self
        else:
            # Appending two bytes Zcash uses for nVersion
            #vs = _bchr(int.from_bytes(self.nVersion[:1], byteorder='big')) + _bchr(int.from_bytes(self.nVersion[1:2], byteorder='big')) + self    #_bchr(self.nVersion[:1]) + _bchr(self.nVersion[1:2]) + self
           #  print("here in not int")
            vs = self.nVersion[:1] + self.nVersion[1:2] + self
        check = zcash.core.Hash(vs)[0:4]
        return encode(vs + check)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

__all__ = (
        'B58_DIGITS',
        'Base58Error',
        'InvalidBase58Error',
        'encode',
        'decode',
        'Base58ChecksumError',
        'CBase58Data',
)
