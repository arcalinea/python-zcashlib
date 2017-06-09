# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import zcash.wallet
import bitcoin.wallet
from zcash.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from zcash.signmessage import BitcoinMessage, VerifyMessage, SignMessage
from bitcoin.wallet import P2PKHBitcoinAddress

import sys
import os
import json

_bchr = chr
_bord = ord
if sys.version > '3':
    long = int
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        return json.load(fd)


class Test_SignVerifyMessage(unittest.TestCase):
    def test_verify_message_simple(self):
        # address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        message = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        signature = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="
        address = zcash.wallet.P2PKHBitcoinAddress.from_bitcoin_address(message)
        message = BitcoinMessage(message)

        self.assertTrue(VerifyMessage(address, message, signature))

    def test_verify_message_vectors(self):
        for vector in load_test_vectors('signmessage.json'):
            message = BitcoinMessage(vector['address'])
            address = zcash.wallet.P2PKHBitcoinAddress.from_bitcoin_address(vector['address'])
            self.assertTrue(VerifyMessage(address, message, vector['signature']))

    def test_sign_message_simple(self):
        key = CBitcoinSecret("L4vB5fomsK8L95wQ7GFzvErYGht49JsCPJyJMHpB4xGM6xgi2jvG")
        address = "t1XthphmzxGm9uGtuyA3z28ieVnc8HoFx6a"
        message = address

        message = BitcoinMessage(message)
        signature = SignMessage(key, message)

        self.assertTrue(signature)
        self.assertTrue(VerifyMessage(address, message, signature))

    def test_sign_message_vectors(self):
        for vector in load_test_vectors('signmessage.json'):
            key = CBitcoinSecret(vector['wif'])
            # print('key:',key)
            # print(vector['address'])
            # print(type(vector['address']))
            #message = BitcoinMessage(zcash.wallet.P2PKHBitcoinAddress.from_bitcoin_address("1K5Z1nxN4mjUgCLpSXMRkeZxuAMpbn2CQB").__str__())
            message = BitcoinMessage(vector['address'])

            address = zcash.wallet.P2PKHBitcoinAddress.from_bitcoin_address(vector['address'])
            # print("address:", address)
            signature = SignMessage(key, message)
            # address2 = zcash.wallet.P2PKHBitcoinAddress.from_privkey(key)
            # print()
            # print("address2:", address2)
            # print("address2bitcoin:", bitcoin.wallet.P2PKHBitcoinAddress.from_pubkey(key.pub))
            
            self.assertTrue(signature, "Failed to sign for [%s]" % vector['address'])
            self.assertTrue(VerifyMessage(address, message, vector['signature']), "Failed to verify signature for [%s]" % message)


if __name__ == "__main__":
    unittest.main()
