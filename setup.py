#!/usr/bin/env python

from distutils.core import setup

setup(
    name='pyaes',
    version='1.0',
    author='Marti Raudsepp',
    author_email='marti@juffo.org',
    description='Simple AES cipher implementation in pure Python',
    license='MIT',
    keywords='aes pypy crypto',
    url='https://bitbucket.org/intgr/pyaes',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Topic :: Security :: Cryptography',
        'Development Status :: 5 - Production/Stable',
    ],
    py_modules=['pyaes'],
)
