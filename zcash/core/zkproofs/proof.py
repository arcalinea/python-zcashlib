# Copyright (C) 2016 Jack Grigg <jack@z.cash>
#
# This file is part of python-zcashlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-zcashlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function

import struct

from zcash.core.serialize import *

G1_PREFIX_MASK = 0x02
G2_PREFIX_MASK = 0x0a

class Fq(Serializable):
    """Element in the base field"""
    def __init__(self, data=b'\x00'*32):
        self.data = data

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f,32)
        return cls(data)

    def stream_serialize(self, f):
        assert len(self.data) == 32
        f.write(self.data)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data == other.data
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

class Fq2(Serializable):
    """Element in the extension field"""
    def __init__(self, data=b'\x00'*64):
        self.data = data

    @classmethod
    def stream_deserialize(cls, f):
        data = ser_read(f,64)
        return cls(data)

    def stream_serialize(self, f):
        assert len(self.data) == 64
        f.write(self.data)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.data == other.data
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

class CompressedG1(Serializable):
    """Compressed point in G1"""
    def __init__(self, y_lsb=False, x=Fq()):
        self.y_lsb = y_lsb
        self.x = x

    @classmethod
    def stream_deserialize(cls, f):
        leadingByte = struct.unpack(b"<B", ser_read(f,1))[0]
        if (leadingByte & (~1)) != G1_PREFIX_MASK:
            raise ValueError("lead byte of G1 point not recognized")
        y_lsb = leadingByte & 1;
        x = Fq.stream_deserialize(f)
        return cls(y_lsb, x)

    def stream_serialize(self, f):
        leadingByte = G1_PREFIX_MASK;
        if self.y_lsb:
            leadingByte |= 1
        f.write(struct.pack(b"<B", leadingByte))
        self.x.stream_serialize(f)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (
                self.y_lsb == other.y_lsb and
                self.x == other.x
            )
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

class CompressedG2(Serializable):
    """Compressed point in G2"""
    def __init__(self, y_gt=False, x=Fq2()):
        self.y_gt = y_gt
        self.x = x

    @classmethod
    def stream_deserialize(cls, f):
        leadingByte = struct.unpack(b"<B", ser_read(f,1))[0]
        if (leadingByte & (~1)) != G2_PREFIX_MASK:
            raise ValueError("lead byte of G2 point not recognized")
        y_gt = leadingByte & 1;
        x = Fq2.stream_deserialize(f)
        return cls(y_gt, x)

    def stream_serialize(self, f):
        leadingByte = G2_PREFIX_MASK;
        if self.y_gt:
            leadingByte |= 1
        f.write(struct.pack(b"<B", leadingByte))
        self.x.stream_serialize(f)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (
                self.y_gt == other.y_gt and
                self.x == other.x
            )
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

class ZCProof(Serializable):
    """Compressed zkSNARK proof"""
    def __init__(self,
                 g_A=CompressedG1(),
                 g_A_prime=CompressedG1,
                 g_B=CompressedG2(),
                 g_B_prime=CompressedG1,
                 g_C=CompressedG1(),
                 g_C_prime=CompressedG1,
                 g_K=CompressedG1(),
                 g_H=CompressedG1()):
        self.g_A       = g_A
        self.g_A_prime = g_A_prime
        self.g_B       = g_B
        self.g_B_prime = g_B_prime
        self.g_C       = g_C
        self.g_C_prime = g_C_prime
        self.g_K       = g_K
        self.g_H       = g_H

    @classmethod
    def stream_deserialize(cls, f):
        g_A       = CompressedG1.stream_deserialize(f)
        g_A_prime = CompressedG1.stream_deserialize(f)
        g_B       = CompressedG2.stream_deserialize(f)
        g_B_prime = CompressedG1.stream_deserialize(f)
        g_C       = CompressedG1.stream_deserialize(f)
        g_C_prime = CompressedG1.stream_deserialize(f)
        g_K       = CompressedG1.stream_deserialize(f)
        g_H       = CompressedG1.stream_deserialize(f)
        return cls(g_A, g_A_prime,
                   g_B, g_B_prime,
                   g_C, g_C_prime,
                   g_K, g_H)

    def stream_serialize(self, f):
        self.g_A.stream_serialize(f)
        self.g_A_prime.stream_serialize(f)
        self.g_B.stream_serialize(f)
        self.g_B_prime.stream_serialize(f)
        self.g_C.stream_serialize(f)
        self.g_C_prime.stream_serialize(f)
        self.g_K.stream_serialize(f)
        self.g_H.stream_serialize(f)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (
                self.g_A == other.g_A and
                self.g_A_prime == other.g_A_prime and
                self.g_B == other.g_B and
                self.g_B_prime == other.g_B_prime and
                self.g_C == other.g_C and
                self.g_C_prime == other.g_C_prime and
                self.g_K == other.g_K and
                self.g_H == other.g_H
            )
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented
