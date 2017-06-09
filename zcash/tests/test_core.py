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

from zcash.core import *

class Test_str_value(unittest.TestCase):
    def test(self):
        def T(value, expected):
            actual = str_money_value(value)
            self.assertEqual(actual, expected)

        T(         0,  '0.0')
        T(         1,  '0.00000001')
        T(        10,  '0.0000001')
        T(  12345678,  '0.12345678')
        T(  10000000,  '0.1')
        T( 100000000,  '1.0')
        T(1000000000, '10.0')
        T(1010000000, '10.1')
        T(1001000000, '10.01')
        T(1012345678, '10.12345678')

class Test_Money(unittest.TestCase):
    def test_MoneyRange(self):
        self.assertFalse(MoneyRange(-1))
        self.assertTrue(MoneyRange(0))
        self.assertTrue(MoneyRange(100000))
        self.assertTrue(MoneyRange(21000000 * COIN)) # Maximum money on zcash network
        self.assertFalse(MoneyRange(21000001 * COIN))

    def test_MoneyRangeCustomParams(self):
        highMaxParamsType = type(str('CoreHighMainParams'), (CoreMainParams,object), {'MAX_MONEY': 22000000 * COIN })
        highMaxParams = highMaxParamsType()
        self.assertTrue(MoneyRange(21000001 * COIN, highMaxParams))
        self.assertTrue(MoneyRange(22000000 * COIN, highMaxParams))
        self.assertFalse(MoneyRange(22000001 * COIN, highMaxParams))

class Test_CBlockHeader(unittest.TestCase):
    def test_serialization(self):
        genesis = CBlockHeader(nVersion=1,
                hashPrevBlock=lx('0000000000000000000000000000000000000000000000000000000000000000'),
                hashMerkleRoot=lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'),
                nTime=1231006505,
                nBits=486604799,
                nNonce=2083236893)
        serialized = genesis.serialize()
        self.assertEqual(Hash(serialized),
                      lx('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'))

        genesis2 = CBlockHeader.deserialize(serialized)
        self.assertEqual(genesis, genesis2)

    def test_GetHash(self):
        genesis = CBlockHeader(nVersion=1,
                hashPrevBlock=lx('0000000000000000000000000000000000000000000000000000000000000000'),
                hashMerkleRoot=lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'),
                nTime=1231006505,
                nBits=486604799,
                nNonce=2083236893)
        self.assertEqual(genesis.GetHash(), lx('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'))

    def test_calc_difficulty(self):
        def T(nbits, expected):
            actual = CBlockHeader.calc_difficulty(nbits)
            actual = round(actual, 3)
            self.assertEqual(actual, expected)

        T(486604799,        1.000) # block 0
        T(486594666,        1.183) # block 33333
        T(469809688,      352.161) # block 74000
        T(453179945,    22012.381) # block 105000
        T(436527338,  3438908.960) # block 210000
        T(426957810, 37392766.136) # block 250000

class Test_CBlock(unittest.TestCase):
    def test_serialization(self):
        initial_serialized = x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000')
        genesis = CBlock.deserialize(initial_serialized)
        serialized = genesis.serialize()
        self.assertEqual(Hash(serialized[0:80]),
                      lx('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'))
        self.assertEqual(serialized, initial_serialized)

    def test_GetHash(self):
        genesis = CBlock.deserialize(x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
        self.assertEqual(genesis.GetHash(), lx('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'))

    def test_calc_merkle_root_of_empty_block(self):
        """CBlock.calc_merkle_root() fails if vtx empty"""
        block = CBlock()
        with self.assertRaises(ValueError):
            block.calc_merkle_root()

    def test_calc_merkle_root(self):
        # genesis
        block = CBlock.deserialize(x('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'))
        self.assertEqual(block.calc_merkle_root(), lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'))
        self.assertEqual(block.vMerkleTree, (lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'),))

        # 170 two transactions
        block = CBlock.deserialize(x('0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e700201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac000000000100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'))
        self.assertEqual(block.calc_merkle_root(), lx('7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff'))

        # 99960 three transactions
        block = CBlock.deserialize(x('01000000e78b20013e6e9a21b6366ead5d866b2f9dc00664508b90f24da8000000000000f94b61259c7e9af3455b277275800d0d6a58b929eedf9e0153a6ef2278a5d53408d11a4d4c86041b0fbf10b00301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b0119ffffffff0100f2052a0100000043410427e729f9cb5564abf2a1ccda596c636b77bd4d9d91f657d4738f3c70fce8ac4e12b1c782905554d9ff2c2e050fdfe3ff93c91c5817e617877d51f450b528c9e4ac000000000100000001e853c9e0c133547fd9e162b1d3860dd0f27d5b9b8a7430d28896c00fbb3f1bc7000000008c49304602210095bcd54ebd0caa7cee75f0f89de472a765e6ef4b98c5fd4b32c7f9d4905db9ae022100ebd3f668e3a1a36d56e30184c27531dbb9fc136c84b1282be562064d86997d1e014104727eb4fdcc90658cd26abe7dcb0ae7297810b15b9e27c32bcf8e3edd934901968806dc18b1276d7273cc4c223feee0070361ed947888a3cef422bebfede96e08ffffffff020065cd1d000000001976a91468c6c2b3c0bc4a8eeb10d16a300d627a31a3b58588ac0008af2f000000001976a9141d87f0a54a1d704ffc70eae83b025698bc0fdcfc88ac00000000010000000125f582f1d37b6713b14b85665a2daea4f464f5ed1c3ab3d4dcf152fb61414b9e000000008a473044022066ec12ced31659e1bf961b542b58bba76ba8f2a1e8f36d5f60be0601598eac21022047ce33685a63283a4c3ebc390261191f215999b2f7d8e1504b8af39aae4a2881014104c5e1d713d10fe59cc48f60701a3efcac418969c22e9c6cf57440f71e44dc82837af5351bf3e1d898f06aa5c792bf0251a39902311d1d27c16847b1b414494f35ffffffff02404b4c00000000001976a91466a3b2e43cfa5c6d9b2f0095f7be5a5cb608478c88ac80b8dc3c030000001976a9146df5ed8cee34df5c05c90406761a11ed143c202d88ac00000000'))
        self.assertEqual(block.calc_merkle_root(), lx('34d5a57822efa653019edfee29b9586a0d0d807572275b45f39a7e9c25614bf9'))

        # 99993 four transactions
        block = CBlock.deserialize(x('01000000acda3db591d5c2c63e8c09e7523a5b0581707ef3e3520d6ca180000000000000701179cb9a9e0fe709cc96261b6b943b31362b61dacba94b03f9b71a06cc2eff7d1c1b4d4c86041b75962f880401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07044c86041b0152ffffffff014034152a01000000434104216220ab283b5e2871c332de670d163fb1b7e509fd67db77997c5568e7c25afd988f19cd5cc5aec6430866ec64b5214826b28e0f7a86458073ff933994b47a5cac0000000001000000042a40ae58b06c3a61ae55dbee05cab546e80c508f71f24ef0cdc9749dac91ea5f000000004a49304602210089c685b37903c4aa62d984929afeaca554d1641f9a668398cd228fb54588f06b0221008a5cfbc5b0a38ba78c4f4341e53272b9cd0e377b2fb740106009b8d7fa693f0b01ffffffff7b999491e30af112b11105cb053bc3633a8a87f44740eb158849a76891ff228b00000000494830450221009a4aa8663ff4017063d2020519f2eade5b4e3e30be69bf9a62b4e6472d1747b2022021ee3b3090b8ce439dbf08a5df31e2dc23d68073ebda45dc573e8a4f74f5cdfc01ffffffffdea82ec2f9e88e0241faa676c13d093030b17c479770c6cc83239436a4327d49000000004a493046022100c29d9de71a34707c52578e355fa0fdc2bb69ce0a957e6b591658a02b1e039d69022100f82c8af79c166a822d305f0832fb800786d831aea419069b3aed97a6edf8f02101fffffffff3e7987da9981c2ae099f97a551783e1b21669ba0bf3aca8fe12896add91a11a0000000049483045022100e332c81781b281a3b35cf75a5a204a2be451746dad8147831255291ebac2604d02205f889a2935270d1bf1ef47db773d68c4d5c6a51bb51f082d3e1c491de63c345601ffffffff0100c817a8040000001976a91420420e56079150b50fb0617dce4c374bd61eccea88ac00000000010000000265a7293b2d69ba51d554cd32ac7586f7fbeaeea06835f26e03a2feab6aec375f000000004a493046022100922361eaafe316003087d355dd3c0ef3d9f44edae661c212a28a91e020408008022100c9b9c84d53d82c0ba9208f695c79eb42a453faea4d19706a8440e1d05e6cff7501fffffffff6971f00725d17c1c531088144b45ed795a307a22d51ca377c6f7f93675bb03a000000008b483045022100d060f2b2f4122edac61a25ea06396fe9135affdabc66d350b5ae1813bc6bf3f302205d8363deef2101fc9f3d528a8b3907e9d29c40772e587dcea12838c574cb80f801410449fce4a25c972a43a6bc67456407a0d4ced782d4cf8c0a35a130d5f65f0561e9f35198349a7c0b4ec79a15fead66bd7642f17cc8c40c5df95f15ac7190c76442ffffffff0200f2052a010000001976a914c3f537bc307c7eda43d86b55695e46047b770ea388ac00cf7b05000000001976a91407bef290008c089a60321b21b1df2d7f2202f40388ac0000000001000000014ab7418ecda2b2531eef0145d4644a4c82a7da1edd285d1aab1ec0595ac06b69000000008c493046022100a796490f89e0ef0326e8460edebff9161da19c36e00c7408608135f72ef0e03e0221009e01ef7bc17cddce8dfda1f1a6d3805c51f9ab2f8f2145793d8e85e0dd6e55300141043e6d26812f24a5a9485c9d40b8712215f0c3a37b0334d76b2c24fcafa587ae5258853b6f49ceeb29cd13ebb76aa79099fad84f516bbba47bd170576b121052f1ffffffff0200a24a04000000001976a9143542e17b6229a25d5b76909f9d28dd6ed9295b2088ac003fab01000000001976a9149cea2b6e3e64ad982c99ebba56a882b9e8a816fe88ac00000000'))
        self.assertEqual(block.calc_merkle_root(), lx('ff2ecc061ab7f9034ba9cbda612b36313b946b1b2696cc09e70f9e9acb791170'))
