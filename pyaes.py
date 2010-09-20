"""Simple AES cipher implementation in Python following PEP 272 API

The first goal of this module is to be as fast as reasonable in Python while
still being Pythonic and readable/understandable. It is licensed under the
permissible MIT license.

Hopefully the code is readable and commented enough that it can serve as an
introduction to the AES cipher for Python coders. In fact, it should go along
well with the Stick Figure Guide to AES:
http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
"""

####
# Copyright (c) 2010 Marti Raudsepp <marti@juffo.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
####


from array import array

MODE_ECB = 1
#MODE_CBC = 2
#MODE_CTR = 6

class AES(object):
    block_size = 16

    def __init__(self, key, mode, IV=None):
        self.mode = mode
        self.IV = IV

        self.setkey(key)

    def setkey(self, key):
        """Sets the key and performs key expansion."""

        self.key = key
        self.key_size = len(key)

        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            raise NotImplementedError
            #self.rounds = 12
        elif self.key_size == 32:
            raise NotImplementedError
            #self.rounds = 14
        else:
            raise ValueError, "Key length must be 16, 24 or 32 bytes"

        self.expand_key()

    def expand_key(self):
        """Performs AES key expansion on self.key and stores in self.exkey"""

        # The key schedule specifies how parts of the key are fed into the
        # cipher's round functions. "Key expansion" means performing this
        # schedule in advance. Almost all implementations do this.
        #
        # Here's a description of AES key schedule:
        # http://en.wikipedia.org/wiki/Rijndael_key_schedule

        # The expanded key starts with the actual key itself
        exkey = array('B', self.key)

        # 4-byte temporary variable for key expansion
        word = exkey[-4:]
        for i in xrange(1, self.rounds + 1):

            #### key schedule core:
            # left-rotate by 1 byte
            word = word[1:4] + word[0:1]

            # apply S-box to all bytes
            for j in xrange(4):
                word[j] = aes_sbox[word[j]]

            # apply the Rcon table to the leftmost byte
            word[0] = word[0] ^ aes_Rcon[i]
            #### end key schedule core

            for z in xrange(4):
                for j in xrange(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

            # TODO: implement expansion for 192- and 256-bit keys

        self.exkey = exkey

    def encrypt(self, data):
        raise NotImplementedError

    def decrypt(self, data):
        raise NotImplementedError


# Globals mandated by PEP 272:
# http://www.python.org/dev/peps/pep-0272/
new = AES
block_size = AES.block_size
key_size = None

# The S-box is a 256-element array, that maps a single byte value to another
# byte value. Since it's designed to be reversible, each value occurs only once
# in the S-box
#
# More information: http://en.wikipedia.org/wiki/Rijndael_S-box

aes_sbox = array('B',
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'.decode('hex')
)

# This is the inverse of the above. In other words:
# aes_inv_sbox[aes_sbox[val]] == val

aes_inv_sbox = array('B',
    '52096ad53036a538bf40a39e81f3d7fb'
    '7ce339829b2fff87348e4344c4dee9cb'
    '547b9432a6c2233dee4c950b42fac34e'
    '082ea16628d924b2765ba2496d8bd125'
    '72f8f66486689816d4a45ccc5d65b692'
    '6c704850fdedb9da5e154657a78d9d84'
    '90d8ab008cbcd30af7e45805b8b34506'
    'd02c1e8fca3f0f02c1afbd0301138a6b'
    '3a9111414f67dcea97f2cfcef0b4e673'
    '96ac7422e7ad3585e2f937e81c75df6e'
    '47f11a711d29c5896fb7620eaa18be1b'
    'fc563e4bc6d279209adbc0fe78cd5af4'
    '1fdda8338807c731b11210592780ec5f'
    '60517fa919b54a0d2de57a9f93c99cef'
    'a0e03b4dae2af5b0c8ebbb3c83539961'
    '172b047eba77d626e169146355210c7d'.decode('hex')
)

# The Rcon table is used in AES's key schedule (key expansion)
# It's a pre-computed table of exponentation of 2 in AES's finite field
#
# More information: http://en.wikipedia.org/wiki/Rijndael_key_schedule

aes_Rcon = array('B',
    '8d01020408102040801b366cd8ab4d9a'
    '2f5ebc63c697356ad4b37dfaefc59139'
    '72e4d3bd61c29f254a943366cc831d3a'
    '74e8cb8d01020408102040801b366cd8'
    'ab4d9a2f5ebc63c697356ad4b37dfaef'
    'c5913972e4d3bd61c29f254a943366cc'
    '831d3a74e8cb8d01020408102040801b'
    '366cd8ab4d9a2f5ebc63c697356ad4b3'
    '7dfaefc5913972e4d3bd61c29f254a94'
    '3366cc831d3a74e8cb8d010204081020'
    '40801b366cd8ab4d9a2f5ebc63c69735'
    '6ad4b37dfaefc5913972e4d3bd61c29f'
    '254a943366cc831d3a74e8cb8d010204'
    '08102040801b366cd8ab4d9a2f5ebc63'
    'c697356ad4b37dfaefc5913972e4d3bd'
    '61c29f254a943366cc831d3a74e8cb'.decode('hex')
)
