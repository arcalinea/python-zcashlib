# python-zcashlib

This Python2/3 library provides an easy interface to the Zcash data
structures and protocol. The approach is low-level and "ground up", with a
focus on providing tools to manipulate the internals of how Zcash works.

This library was originally forked from python-bitcoinlib.

## Requirements

    sudo apt-get install libssl-dev

The RPC interface, zcash.rpc, is designed to work with Zcash v1.0.0
Older versions may not work.

## Structure

Everything consensus critical is found in the modules under zcash.core. This
rule is followed pretty strictly, for instance chain parameters are split into
consensus critical and non-consensus-critical.

    zcash.core            - Basic core definitions, datastructures, and
                              (context-independent) validation
    zcash.core.key        - ECC pubkeys
    zcash.core.script     - Scripts and opcodes
    zcash.core.scripteval - Script evaluation/verification
    zcash.core.serialize  - Serialization

In the future the zcash.core may use the Satoshi sourcecode directly as a
library. Non-consensus critical modules include the following:

    zcash          - Chain selection
    zcash.base58   - Base58 encoding
    zcash.bloom    - Bloom filters (incomplete)
    zcash.net      - Network communication (in flux)
    zcash.messages - Network messages (in flux)
    zcash.rpc      - Zcash RPC interface support
    zcash.wallet   - Wallet-related code, currently Zcash t-address and
                       private key support

Functions related to Zcash's zero-knowledge proofs resides under `zcash.core.zkproofs`.

Effort has been made to follow the Satoshi source relatively closely, for
instance Python code and classes that duplicate the functionality of
corresponding Satoshi C++ code uses the same naming conventions: CTransaction,
CBlockHeader, nValue etc. Otherwise Python naming conventions are followed.


## Mutable vs. Immutable objects

Like the Zcash codebase CTransaction is immutable and
CMutableTransaction is mutable; unlike the Zcash codebase this
distinction also applies to COutPoint, CTxIn, CTxOut, and CBlock.


## Endianness Gotchas

Rather confusingly, Bitcoin and thus Zcash shows transaction and block hashes as
little-endian hex rather than the big-endian, which the rest of the world uses for
SHA256. python-zcashlib provides the convenience functions x() and lx() in
zcash.core to convert from big-endian and little-endian hex to raw bytes to
accomodate this. In addition see b2x() and b2lx() for conversion from bytes to
big/little-endian hex.


## Module import style

While not always good style, it's often convenient for quick scripts if
`import *` can be used. To support that all the modules have `__all__` defined
appropriately.


# Example Code

See `examples/` directory. For instance this example creates a transaction
spending a pay-to-script-hash transaction output:

    $ PYTHONPATH=. examples/spend-pay-to-script-hash-txout.py
    <hex-encoded transaction>


## Selecting the chain to use

Do the following:

    import zcash
    zcash.SelectParams(NAME)

Where NAME is one of 'testnet', 'mainnet', or 'regtest'. The chain currently
selected is a global variable that changes behavior everywhere, just like in
the Satoshi codebase.


## Unit tests

Under zcash/tests using test data from Zcash. To run them:

    python -m unittest discover && python3 -m unittest discover

Please run the tests on both Python2 and Python3 for your pull-reqs!

Alternately, if Tox (see https://tox.readthedocs.org/) is available on your
system, you can run unit tests for multiple Python versions:

    ./runtests.sh

Currently, the following implementations are tried (any not installed are
skipped):

    * CPython 2.7
    * CPython 3.3
    * CPython 3.4
    * CPython 3.5
    * PyPy
    * PyPy3

HTML coverage reports can then be found in the htmlcov/ subdirectory.

## Documentation

**TODO** Documentation is not updated for Zcash.

Sphinx documentation is in the "doc" subdirectory. Run "make help" from there
to see how to build. You will need the Python "sphinx" package installed.

Currently this is just API documentation generated from the code and
docstrings. Higher level written docs would be useful, perhaps starting with
much of this README. Pages are written in reStructuredText and linked from
index.rst.
