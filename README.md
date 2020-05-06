## pyaes is:

* **an implementation of AES** (Advanced Encryption Standard) cipher in **pure Python**, including ECB & CBC modes
* **easy to use:** it has a simple [PEP 272 cipher API](https://www.python.org/dev/peps/pep-0272/), like PyCrypto
* **not too slow:** it's as fast as Python permits without obfuscating the code
* **well-tested:** it includes a test runner to check the operation against NIST published test vectors
* **raw cipher only:** it does not do padding/verification/key derivation -- any secure crypto protocol should
* **liberal:** Licensed under the [permissive MIT license](https://opensource.org/licenses/MIT)

### Show me the code!

**[View in browser](./pyaes.py)**

### How?

```python
>>> import pyaes
>>> cryptor = pyaes.new('secret_secretkey', pyaes.MODE_CBC, IV='_some_random_iv_')
>>> ciphertext = cryptor.encrypt('This is a test! What could possibly go wrong?___')
>>> ciphertext
'S8\n\x81\xee3\x86\xd6\t\xf8\xc6\xde~\xdc\x14H#\xd2\xe1\xda\xd79\x81\xb7'
'>\xdd\xed\xaa\xed\xcfp\xee\xc6\x8f(\xdc\xb1A"\xe9[\x9f{\x8e\xa6F\xfbQ'
>>> decryptor = pyaes.new('secret_secretkey', pyaes.MODE_CBC, IV='_some_random_iv_')
>>> decryptor.decrypt(ciphertext)
'This is a test! What could possibly go wrong?___'
```

### Caveats

Please beware that the nature of Python makes cryptography susceptible to
[timing attacks](https://en.wikipedia.org/wiki/Timing_attack). Python (and
other interpreted languages) introduce lots of data-dependent branches and have
a higher cache footprint than native code. Their general slowness also makes it
easier to measure timing variations. **When in doubt, always use native code
cryptography like [pycryptodome](https://www.pycryptodome.org/)**.

### Why?

The main motivation for writing this was to provide the
[PyPy project](https://www.pypy.org/) with a crypto benchmark for
[speed.pypy.org](https://speed.pypy.org/).

I was looking at the [SlowAES project](https://code.google.com/archive/p/slowaes/)
first; it was very slow, so I created an optimization branch of it. However, I
still wasn't happy with the way the code was written. Its legacy as C code that
was converted to JavaScript, then converted to Python, was showing. The API was
also weird by Python standards.

So pyaes was born! Written from scratch to be Pythonic and benchmark-quality.

### Speed

Even though pyaes is an optimized Python implementation, Python itself is still slow. It should be capable of around **80 kB/s** on modern hardware; that's **1000x slower** than pure C implementations.

If you have any ideas how to make it faster, I'm interested in hearing your thoughts. :)
