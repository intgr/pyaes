#!/usr/bin/env python

"""Test the AES implementation against NIST published AES KAT test vectors

Actual data files are in the KAT_AES/ directory. Can be downloaded here:
http://csrc.nist.gov/groups/STM/cavp/index.html
"""

import os
import sys
import unittest

# Some magic to locate the 'pyaes' module relative to tests
path = os.path.dirname(__file__)
if path and path != '.':
    sys.path.append(os.path.dirname(path))
else:
    sys.path.append(os.path.dirname(os.getcwd()))

import pyaes

class KATRunner(object):
    def run(self, filename):
        self.iv = None
        self.key = None
        self.ciphertext = None
        self.plaintext = None
        self.function = None
        self.mode = None

        self.cnt_ok = 0
        self.cnt_skipped = 0

        f = open(filename, 'rb')

        # detect mode
        self.basename = basename = os.path.basename(filename)
        if basename.startswith('ECB'):
            self.mode = pyaes.MODE_ECB
        elif basename.startswith('CBC'):
            self.mode = pyaes.MODE_CBC
        else:
            #print basename, 'Unrecognized mode, skipping.'
            return

        for line in f:
            line = line.strip()

            if line == '':
                continue
            elif line == '[ENCRYPT]':
                self.function = 'encrypt'
            elif line == '[DECRYPT]':
                self.function = 'decrypt'
            else:
                param, eq, value = line.split(' ', 2)

                if param == 'COUNT':
                    if value != '0':
                        self.do_test()

                    self.test_no = int(value)
                else:
                    setattr(self, param.lower(), value.decode('hex'))

        # at the end of file, run the test
        self.do_test()

        print '%s: %3d OK %3d skipped' % (basename, self.cnt_ok, self.cnt_skipped)

    def do_test(self):
        aes = pyaes.new(self.key, self.mode, self.iv)

        if self.function == 'encrypt':
            ciphertext = aes.encrypt(self.plaintext)
            assert self.ciphertext == ciphertext
        else:
            assert self.function == 'decrypt'
            plaintext = aes.decrypt(self.ciphertext)
            assert self.plaintext == plaintext

        self.cnt_ok += 1

if __name__ == '__main__':
    import glob

    runner = KATRunner()

    files = sys.argv[1:]
    if not files:
        files = glob.glob('KAT_AES/CBC*.txt') + glob.glob('KAT_AES/ECB*.txt')
        files.sort()

    for filename in files:
        runner.run(filename)

