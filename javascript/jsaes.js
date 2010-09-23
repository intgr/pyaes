/* Simple AES cipher implementation in pure JavaScript
 *
 * Hopefully the code is readable and commented enough that it can serve as an
 * introduction to the AES cipher for Python coders. In fact, it should go along
 * well with the Stick Figure Guide to AES:
 * http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
 *
 * Contrary to intuition, this implementation numbers the 4x4 matrices from top to
 * bottom for efficiency reasons:
 *
 *  0  4  8 12
 *  1  5  9 13
 *  2  6 10 14
 *  3  7 11 15
 *
 * Effectively it's the transposition of what you'd expect. This actually makes
 * the code simpler -- except the ShiftRows step, but hopefully the explanation
 * there clears it up.
 */

/****
 * Copyright (c) 2010 Marti Raudsepp <marti@juffo.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ****/

// namespace
jsaes = {};

jsaes.mode = { ECB: 1, CBC: 2 };

// This is the initialization function to call if you want ECB/CBC encryption
jsaes.create = function create(key, mode, iv) {
    if (mode == jsaes.mode.ECB)
        return new jsaes.ECBMode(new jsaes.AES(key));

    else if (mode == jsaes.mode.CBC) {
        if (!iv) {
            // TODO raise ValueError, "CBC mode needs an IV value!"
            return;
        }
        //return jsaes.CBCMode(jsaes.AES(key), iv);
        aes = new jsaes.AES(key);
        return new jsaes.CBCMode(aes, iv);
    }
}

// AES cipher class
jsaes.AES = function AES(key) {
    this.setKey(key);
}

jsaes.AES.prototype.blockSize=16;

// Sets the key and performs key expansion
jsaes.AES.prototype.setKey = function setKey(key) {
    this.key = key;
    this.keySize = key.length;

    if (this.keySize == 16)
        this.rounds=10;
    else if (this.keySize == 24)
        this.rounds=12;
    else if (this.keySize == 32)
            this.rounds=14;
    else {
        // TODO throw ValueError('Key length must be 16, 24 or 32 bytes');
        return;
    }

    this.expandKey();
}

/* Performs AES key expansion on this.key and stores in this.exKey
 *
 * The key schedule specifies how parts of the key are fed into the
 * cipher's round functions. "Key expansion" means performing this
 * schedule in advance. Almost all implementations do this.
 *
 * Here's a description of AES key schedule:
 * http://en.wikipedia.org/wiki/Rijndael_key_schedule
 */
jsaes.AES.prototype.expandKey = function expandKey() {
    var exKey;
    var j, z;

    // XXX exKey=py2js_map(ord, this.key);
    // The expanded key starts with the actual key itself; copy it
    exKey = this.key.slice();

    // extra key expansion steps
    var extraCount;
    if (this.keySize == 16)
        var extraCount=0;
    else if (this.keySize == 24)
        var extraCount=2;
    else
        var extraCount=3;

    // 4-byte temporary variable for key expansion
    var word = exKey.slice(-4);

    // Each expansion cycle uses 'i' once for Rcon table lookup
    for(var i = 1; i < 11; i++) {
        //// key schedule core:
        // left-rotate by 1 byte
        word = word.slice(1,4).concat(word.slice(0,1));

        // apply S-box to all bytes
        for(j = 0; j < 4; j++) {
            word[j] = jsaes.sbox[(word[j])];
        }

        // apply the Rcon table to the leftmost byte
        word[0] ^= jsaes.rcon[i];

        for(z = 0; z < 4; z++) {
            for(j = 0; j < 4; j++) {
                // mix in bytes from the last subkey
                word[j] ^= exKey[exKey.length - this.keySize + j];
            }
            exKey = exKey.concat(word);
        }

        // Last key expansion cycle always finishes here
        if (exKey.length >= ((this.rounds+1) * this.blockSize)) {
            break;
        }

        // Special substitution step for 256-bit key
        if (this.keySize == 32) {
            for(j=0;j<4;j++) {
                // mix in bytes from the last subkey XORed with S-box of
                // current word bytes
                word[j] = jsaes.sbox[word[j]] ^ exKey[exKey.length - this.keySize + j];
            }
            exKey = exKey.concat(word);
        }

        // Twice for 192-bit key, thrice for 256-bit key
        for(z=0; z < extraCount; z++) {
            for(j = 0; j < 4; j++) {
                // mix in bytes from the last subkey
                word[j] ^= exKey[exKey.length - this.keySize + j];
            }
            exKey = exKey.concat(word);
        }
    }
    this.exKey=exKey;
}

// Encrypts a single block. This is the main AES function
jsaes.AES.prototype.encryptBlock = function encryptBlock(block) {
    this.addRoundKey(block, 0);

    // For efficiency reasons, the state between steps is transmitted via a
    // mutable array, not returned
    for(var round = 1; round < this.rounds; round++) {
        this.subBytes(block, jsaes.sbox);
        this.shiftRows(block);
        this.mixColumns(block);
        this.addRoundKey(block, round);
    }
    this.subBytes(block, jsaes.sbox);
    this.shiftRows(block);
    // no mix_columns step in the last round
    this.addRoundKey(block, this.rounds);
}

// Decrypts a single block. This is the main AES decryption function
jsaes.AES.prototype.decryptBlock = function decryptBlock(block) {
    this.addRoundKey(block, this.rounds);

    // For efficiency reasons, the state between steps is transmitted via a
    // mutable array, not returned
    for(var round = (this.rounds - 1); round > 0; round--) {
        this.shiftRowsInv(block);
        this.subBytes(block, jsaes.invSbox);
        this.addRoundKey(block, round);
        this.mixColumnsInv(block);
    }
    this.shiftRowsInv(block);
    this.subBytes(block, jsaes.invSbox);
    this.addRoundKey(block, 0);
    // no mix_columns step in the last round
}

// AddRoundKey step in AES. This is where the key is mixed into plaintext
jsaes.AES.prototype.addRoundKey = function addRoundKey(block, round) {
    var offset = round * 16;
    var exKey = this.exKey;

    for(var i = 0; i < 16; i++) {
        block[i] ^= exKey[offset + i];
    }

    //console.log('AddRoundKey: ' + block)
}

/* SubBytes step, apply S-box to all bytes
 *
 * Depending on whether encrypting or decrypting, a different sbox array
 * is passed in.
 */
jsaes.AES.prototype.subBytes = function subBytes(block, sbox) {
    for(var i = 0; i < 16; i++) {
        block[i] = sbox[block[i]];
    }

    //console.log('SubBytes   : ' + block)
}

/* ShiftRows step. Shifts 2nd row to left by 1, 3rd row by 2, 4th row by 3
 *
 * Since we're performing this on a transposed matrix, cells are numbered
 * from top to bottom first:
 *
 * 0  4  8 12   ->    0  4  8 12    -- 1st row doesn't change
 * 1  5  9 13   ->    5  9 13  1    -- row shifted to left by 1 (wraps around)
 * 2  6 10 14   ->   10 14  2  6    -- shifted by 2
 * 3  7 11 15   ->   15  3  7 11    -- shifted by 3
 */
jsaes.AES.prototype.shiftRows = function shiftRows(b) {
    var tmp;

    // 2nd row
    tmp  = b[1];
    b[1] = b[5];
    b[5] = b[9];
    b[9] = b[13];
    b[13]= tmp;

    // 3rd row
    tmp  = b[2];
    b[2] = b[10];
    b[10]= tmp;
    tmp  = b[6];
    b[6] = b[14];
    b[14]= tmp;

    // 4th row
    tmp  = b[15];
    b[15]= b[11];
    b[11]= b[7];
    b[7] = b[3];
    b[3] = tmp;

    //console.log('ShiftRows  : ' + b)
}

// Similar to shiftRows above, but performed in inverse for decryption
jsaes.AES.prototype.shiftRowsInv = function shiftRowsInv(b) {
    var tmp;

    // 2nd row
    tmp  = b[13];
    b[13]= b[9];
    b[9] = b[5];
    b[5] = b[1];
    b[1] = tmp;

    // 3rd row
    tmp  = b[2];
    b[2] = b[10];
    b[10]= tmp;
    tmp  = b[6];
    b[6] = b[14];
    b[14]= tmp;

    // 4th row
    tmp  = b[3];
    b[3] = b[7];
    b[7] = b[11];
    b[11]= b[15];
    b[15]= tmp;

    //console.log('ShiftRows  : ' + b)
}

// MixColumns step. Mixes the values in each column
jsaes.AES.prototype.mixColumns = function mixColumns(block) {
    var mulBy2 = jsaes.gfMulBy2;
    var mulBy3 = jsaes.gfMulBy3;

    for(var col = 0; col < 16; col += 4) {
        var v0 = block[col  ];
        var v1 = block[col+1];
        var v2 = block[col+2];
        var v3 = block[col+3];

        block[col  ] = mulBy2[v0] ^ v3 ^ v2 ^ mulBy3[v1];
        block[col+1] = mulBy2[v1] ^ v0 ^ v3 ^ mulBy3[v2];
        block[col+2] = mulBy2[v2] ^ v1 ^ v0 ^ mulBy3[v3];
        block[col+3] = mulBy2[v3] ^ v2 ^ v1 ^ mulBy3[v0];
    }

    //console.log('MixColumns : ' + block)
}

// Similar to mixColumns above, but performed in inverse for decryption.
jsaes.AES.prototype.mixColumnsInv = function mixColumnsInv(block) {
    var mul9 = jsaes.gfMulBy9;
    var mul11 = jsaes.gfMulBy11;
    var mul13 = jsaes.gfMulBy13;
    var mul14 = jsaes.gfMulBy14;

    for(var col = 0; col < 16; col += 4) {
        var v0 = block[col  ];
        var v1 = block[col+1];
        var v2 = block[col+2];
        var v3 = block[col+3];

        block[col  ] = mul14[v0] ^ mul9[v3] ^ mul13[v2] ^ mul11[v1];
        block[col+1] = mul14[v1] ^ mul9[v0] ^ mul13[v3] ^ mul11[v2];
        block[col+2] = mul14[v2] ^ mul9[v1] ^ mul13[v0] ^ mul11[v3];
        block[col+3] = mul14[v3] ^ mul9[v2] ^ mul13[v1] ^ mul11[v0];
    }

    //console.log('MixColumns : ' + block)
}

/********
 * Class for Electronic CodeBook (ECB) mode encryption.
 *
 * Basically this mode applies the cipher function to each block individually;
 * no feedback is done. NB! This is insecure for almost all purposes
 */
jsaes.ECBMode = function ECBMode(cipher) {
    this.cipher = cipher;
    this.blockSize = cipher.blockSize;
}

// Encrypt data in ECB mode
jsaes.ECBMode.prototype.encrypt = function encrypt(data) {
    return this.ecb(data, this.cipher.encryptBlock);
}

// Decrypt data in ECB mode
jsaes.ECBMode.prototype.decrypt = function decrypt(data) {
    return this.ecb(data, this.cipher.decryptBlock);
}

// Perform ECB mode with the given function
jsaes.ECBMode.prototype.ecb = function ecb(data, blockFunc) {
    if (data.length % blockSize != 0) {
        // TODO throw ValueError('Input length must be multiple of 16');
        return;
    }
    var blockSize = this.blockSize;

    // XXX var data = py2js_map(ord, data);
    var result = new Array;

    for(var offset = 0; offset < data.length; offset += blockSize) {
        var block = data.slice(offset, offset + blockSize);

        blockFunc(block);

        for(var i = 0; i < blockSize; i++) {
            result.push(block[i]);
        }
    }

    return result;
}


/********
 * Cipher Block Chaining (CBC) mode encryption. This mode avoids content leaks.
 *
 * In CBC encryption, each plaintext block is XORed with the ciphertext block
 * preceding it; decryption is simply the inverse.
 *
 * A better explanation of CBC can be found here:
 * http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
jsaes.CBCMode = function CBCMode(cipher, iv) {
    this.cipher = cipher;
    this.blockSize = cipher.blockSize;
    this.iv = iv;
}

// Encrypt data in CBC mode
jsaes.CBCMode.prototype.encrypt = function encrypt(data) {
    var blockSize = this.blockSize;

    if (data.length % blockSize != 0) {
        // TODO throw ValueError('Ciphertext length must be multiple of 16');
        return;
    }

    // XXX var data = py2js_map(ord, data);
    var result = new Array;
    var iv = this.iv;

    for(var offset = 0; offset < data.length; offset += blockSize) {
        var block = data.slice(offset, offset + blockSize);

        // Perform CBC chaining
        for(var i = 0; i < blockSize; i++) {
            block[i] ^= iv[i];
        }
        this.cipher.encryptBlock(block);

        for(var i = 0; i < blockSize; i++) {
            result.push(block[i]);
        }

        iv = block;
    }
    this.iv = iv;

    return result;
}

// Decrypt data in CBC mode
jsaes.CBCMode.prototype.decrypt = function decrypt(data) {
    var blockSize = this.blockSize;

    if (data.length % blockSize != 0) {
        // TODO throw ValueError('Ciphertext length must be multiple of 16');
        return;
    }

    // XXX var data = py2js_map(ord, data);
    var result = new Array;
    var iv = this.iv;

    for(var offset = 0; offset < data.length; offset += blockSize) {
        var ctext = data.slice(offset, offset + blockSize);

        // copy array, we'll need ctext later
        var block = ctext.slice();
        this.cipher.decryptBlock(block);

        // Perform CBC chaining
        for(var i = 0; i < blockSize; i++) {
            result.push(block[i] ^ iv[i])
        }

        iv = ctext;
    }

    this.iv = iv;
    return result;
}

/********
 * The S-box is a 256-element array, that maps a single byte value to another
 * byte value. Since it's designed to be reversible, each value occurs only once
 * in the S-box
 *
 * More information: http://en.wikipedia.org/wiki/Rijndael_S-box
 */
jsaes.sbox = [
     99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
    202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
    183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
      4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
      9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
     83,209,  0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
    208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
     81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
    205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
     96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
    224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
    231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
    186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
    112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
    225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
    140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
]

/* This is the inverse of the above. In other words:
 * invSbox[sbox[val]] == val
 */
jsaes.invSbox = [
     82,  9,106,213, 48, 54,165, 56,191, 64,163,158,129,243,215,251,
    124,227, 57,130,155, 47,255,135, 52,142, 67, 68,196,222,233,203,
     84,123,148, 50,166,194, 35, 61,238, 76,149, 11, 66,250,195, 78,
      8, 46,161,102, 40,217, 36,178,118, 91,162, 73,109,139,209, 37,
    114,248,246,100,134,104,152, 22,212,164, 92,204, 93,101,182,146,
    108,112, 72, 80,253,237,185,218, 94, 21, 70, 87,167,141,157,132,
    144,216,171,  0,140,188,211, 10,247,228, 88,  5,184,179, 69,  6,
    208, 44, 30,143,202, 63, 15,  2,193,175,189,  3,  1, 19,138,107,
     58,145, 17, 65, 79,103,220,234,151,242,207,206,240,180,230,115,
    150,172,116, 34,231,173, 53,133,226,249, 55,232, 28,117,223,110,
     71,241, 26,113, 29, 41,197,137,111,183, 98, 14,170, 24,190, 27,
    252, 86, 62, 75,198,210,121, 32,154,219,192,254,120,205, 90,244,
     31,221,168, 51,136,  7,199, 49,177, 18, 16, 89, 39,128,236, 95,
     96, 81,127,169, 25,181, 74, 13, 45,229,122,159,147,201,156,239,
    160,224, 59, 77,174, 42,245,176,200,235,187, 60,131, 83,153, 97,
     23, 43,  4,126,186,119,214, 38,225,105, 20, 99, 85, 33, 12,125,
]

/* The Rcon table is used in AES's key schedule (key expansion)
 * It's a pre-computed table of exponentation of 2 in AES's finite field
 *
 * More information: http://en.wikipedia.org/wiki/Rijndael_key_schedule
 */
jsaes.rcon = [
    141,  1,  2,  4,  8, 16, 32, 64,128, 27, 54,108,216,171, 77,154,
     47, 94,188, 99,198,151, 53,106,212,179,125,250,239,197,145, 57,
    114,228,211,189, 97,194,159, 37, 74,148, 51,102,204,131, 29, 58,
    116,232,203,141,  1,  2,  4,  8, 16, 32, 64,128, 27, 54,108,216,
    171, 77,154, 47, 94,188, 99,198,151, 53,106,212,179,125,250,239,
    197,145, 57,114,228,211,189, 97,194,159, 37, 74,148, 51,102,204,
    131, 29, 58,116,232,203,141,  1,  2,  4,  8, 16, 32, 64,128, 27,
     54,108,216,171, 77,154, 47, 94,188, 99,198,151, 53,106,212,179,
    125,250,239,197,145, 57,114,228,211,189, 97,194,159, 37, 74,148,
     51,102,204,131, 29, 58,116,232,203,141,  1,  2,  4,  8, 16, 32,
     64,128, 27, 54,108,216,171, 77,154, 47, 94,188, 99,198,151, 53,
    106,212,179,125,250,239,197,145, 57,114,228,211,189, 97,194,159,
     37, 74,148, 51,102,204,131, 29, 58,116,232,203,141,  1,  2,  4,
      8, 16, 32, 64,128, 27, 54,108,216,171, 77,154, 47, 94,188, 99,
    198,151, 53,106,212,179,125,250,239,197,145, 57,114,228,211,189,
     97,194,159, 37, 74,148, 51,102,204,131, 29, 58,116,232,203,
]

// Lookup table for AES Galois Field multiplication by 2
jsaes.gfMulBy2 = [
      0,  2,  4,  6,  8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
     32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
     64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
     96, 98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
    128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
    160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
    192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
    224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
     27, 25, 31, 29, 19, 17, 23, 21, 11,  9, 15, 13,  3,  1,  7,  5,
     59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
     91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
    123,121,127,125,115,113,119,117,107,105,111,109, 99, 97,103,101,
    155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
    187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
    219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
    251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229,
]

// GF multiplication by 3
jsaes.gfMulBy3 = [
      0,  3,  6,  5, 12, 15, 10,  9, 24, 27, 30, 29, 20, 23, 18, 17,
     48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33,
     96, 99,102,101,108,111,106,105,120,123,126,125,116,119,114,113,
     80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65,
    192,195,198,197,204,207,202,201,216,219,222,221,212,215,210,209,
    240,243,246,245,252,255,250,249,232,235,238,237,228,231,226,225,
    160,163,166,165,172,175,170,169,184,187,190,189,180,183,178,177,
    144,147,150,149,156,159,154,153,136,139,142,141,132,135,130,129,
    155,152,157,158,151,148,145,146,131,128,133,134,143,140,137,138,
    171,168,173,174,167,164,161,162,179,176,181,182,191,188,185,186,
    251,248,253,254,247,244,241,242,227,224,229,230,239,236,233,234,
    203,200,205,206,199,196,193,194,211,208,213,214,223,220,217,218,
     91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74,
    107,104,109,110,103,100, 97, 98,115,112,117,118,127,124,121,122,
     59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42,
     11,  8, 13, 14,  7,  4,  1,  2, 19, 16, 21, 22, 31, 28, 25, 26,
]

// GF multiplication by 9
jsaes.gfMulBy9 = [
      0,  9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83,108,101,126,119,
    144,153,130,139,180,189,166,175,216,209,202,195,252,245,238,231,
     59, 50, 41, 32, 31, 22, 13,  4,115,122, 97,104, 87, 94, 69, 76,
    171,162,185,176,143,134,157,148,227,234,241,248,199,206,213,220,
    118,127,100,109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19,  8,  1,
    230,239,244,253,194,203,208,217,174,167,188,181,138,131,152,145,
     77, 68, 95, 86,105, 96,123,114,  5, 12, 23, 30, 33, 40, 51, 58,
    221,212,207,198,249,240,235,226,149,156,135,142,177,184,163,170,
    236,229,254,247,200,193,218,211,164,173,182,191,128,137,146,155,
    124,117,110,103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25,  2, 11,
    215,222,197,204,243,250,225,232,159,150,141,132,187,178,169,160,
     71, 78, 85, 92, 99,106,113,120, 15,  6, 29, 20, 43, 34, 57, 48,
    154,147,136,129,190,183,172,165,210,219,192,201,246,255,228,237,
     10,  3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89,102,111,116,125,
    161,168,179,186,133,140,151,158,233,224,251,242,205,196,223,214,
     49, 56, 35, 42, 21, 28,  7, 14,121,112,107, 98, 93, 84, 79, 70,
]

// GF multiplication by 11
jsaes.gfMulBy11 = [
      0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69,116,127, 98,105,
    176,187,166,173,156,151,138,129,232,227,254,245,196,207,210,217,
    123,112,109,102, 87, 92, 65, 74, 35, 40, 53, 62, 15,  4, 25, 18,
    203,192,221,214,231,236,241,250,147,152,133,142,191,180,169,162,
    246,253,224,235,218,209,204,199,174,165,184,179,130,137,148,159,
     70, 77, 80, 91,106, 97,124,119, 30, 21,  8,  3, 50, 57, 36, 47,
    141,134,155,144,161,170,183,188,213,222,195,200,249,242,239,228,
     61, 54, 43, 32, 17, 26,  7, 12,101,110,115,120, 73, 66, 95, 84,
    247,252,225,234,219,208,205,198,175,164,185,178,131,136,149,158,
     71, 76, 81, 90,107, 96,125,118, 31, 20,  9,  2, 51, 56, 37, 46,
    140,135,154,145,160,171,182,189,212,223,194,201,248,243,238,229,
     60, 55, 42, 33, 16, 27,  6, 13,100,111,114,121, 72, 67, 94, 85,
      1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68,117,126, 99,104,
    177,186,167,172,157,150,139,128,233,226,255,244,197,206,211,216,
    122,113,108,103, 86, 93, 64, 75, 34, 41, 52, 63, 14,  5, 24, 19,
    202,193,220,215,230,237,240,251,146,153,132,143,190,181,168,163,
]

// GF multiplication by 13
jsaes.gfMulBy13 = [
      0, 13, 26, 23, 52, 57, 46, 35,104,101,114,127, 92, 81, 70, 75,
    208,221,202,199,228,233,254,243,184,181,162,175,140,129,150,155,
    187,182,161,172,143,130,149,152,211,222,201,196,231,234,253,240,
    107,102,113,124, 95, 82, 69, 72,  3, 14, 25, 20, 55, 58, 45, 32,
    109, 96,119,122, 89, 84, 67, 78,  5,  8, 31, 18, 49, 60, 43, 38,
    189,176,167,170,137,132,147,158,213,216,207,194,225,236,251,246,
    214,219,204,193,226,239,248,245,190,179,164,169,138,135,144,157,
      6, 11, 28, 17, 50, 63, 40, 37,110, 99,116,121, 90, 87, 64, 77,
    218,215,192,205,238,227,244,249,178,191,168,165,134,139,156,145,
     10,  7, 16, 29, 62, 51, 36, 41, 98,111,120,117, 86, 91, 76, 65,
     97,108,123,118, 85, 88, 79, 66,  9,  4, 19, 30, 61, 48, 39, 42,
    177,188,171,166,133,136,159,146,217,212,195,206,237,224,247,250,
    183,186,173,160,131,142,153,148,223,210,197,200,235,230,241,252,
    103,106,125,112, 83, 94, 73, 68, 15,  2, 21, 24, 59, 54, 33, 44,
     12,  1, 22, 27, 56, 53, 34, 47,100,105,126,115, 80, 93, 74, 71,
    220,209,198,203,232,229,242,255,180,185,174,163,128,141,154,151,
]

// GF multiplication by 14
jsaes.gfMulBy14 = [
      0, 14, 28, 18, 56, 54, 36, 42,112,126,108, 98, 72, 70, 84, 90,
    224,238,252,242,216,214,196,202,144,158,140,130,168,166,180,186,
    219,213,199,201,227,237,255,241,171,165,183,185,147,157,143,129,
     59, 53, 39, 41,  3, 13, 31, 17, 75, 69, 87, 89,115,125,111, 97,
    173,163,177,191,149,155,137,135,221,211,193,207,229,235,249,247,
     77, 67, 81, 95,117,123,105,103, 61, 51, 33, 47,  5, 11, 25, 23,
    118,120,106,100, 78, 64, 82, 92,  6,  8, 26, 20, 62, 48, 34, 44,
    150,152,138,132,174,160,178,188,230,232,250,244,222,208,194,204,
     65, 79, 93, 83,121,119,101,107, 49, 63, 45, 35,  9,  7, 21, 27,
    161,175,189,179,153,151,133,139,209,223,205,195,233,231,245,251,
    154,148,134,136,162,172,190,176,234,228,246,248,210,220,206,192,
    122,116,102,104, 66, 76, 94, 80, 10,  4, 22, 24, 50, 60, 46, 32,
    236,226,240,254,212,218,200,198,156,146,128,142,164,170,184,182,
     12,  2, 16, 30, 52, 58, 40, 38,124,114, 96,110, 68, 74, 88, 86,
     55, 57, 43, 37, 15,  1, 19, 29, 71, 73, 91, 85,127,113, 99,109,
    215,217,203,197,239,225,243,253,167,169,187,181,159,145,131,141,
]
