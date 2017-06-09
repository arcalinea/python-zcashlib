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

# Zcash definitions
ZC_NUM_JS_INPUTS = 2
ZC_NUM_JS_OUTPUTS = 2
INCREMENTAL_MERKLE_TREE_DEPTH = 29
INCREMENTAL_MERKLE_TREE_DEPTH_TESTING = 4

ZC_NOTEPLAINTEXT_LEADING = 1
ZC_V_SIZE = 8
ZC_RHO_SIZE = 32
ZC_R_SIZE = 32
ZC_MEMO_SIZE = 512

ZC_NOTEPLAINTEXT_SIZE = ZC_NOTEPLAINTEXT_LEADING + ZC_V_SIZE + ZC_RHO_SIZE + ZC_R_SIZE + ZC_MEMO_SIZE

NOTEENCRYPTION_AUTH_BYTES = 16

ZC_NOTECIPHERTEXT_SIZE = ZC_NOTEPLAINTEXT_SIZE + NOTEENCRYPTION_AUTH_BYTES
