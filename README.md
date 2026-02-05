# node-jwa [![Build Status](https://travis-ci.org/brianloveswords/node-jwa.svg?branch=master)](https://travis-ci.org/brianloveswords/node-jwa)

A
[JSON Web Algorithms](http://tools.ietf.org/id/draft-ietf-jose-json-web-algorithms-08.html)
implementation focusing (exclusively, at this point) on the algorithms necessary for
[JSON Web Signatures](http://self-issued.info/docs/draft-ietf-jose-json-web-signature.html).

This library supports all of the required, recommended and optional cryptographic algorithms for JWS:

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
PS256 | RSASSA-PSS using SHA-256 hash algorithm
PS384 | RSASSA-PSS using SHA-384 hash algorithm
PS512 | RSASSA-PSS using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included

## Features

- **ES Modules Only**: Pure ESM implementation
- **Standards-Based Cryptography**: Uses Web Crypto API (SubtleCrypto) for all operations
- **Cross-Environment Compatible**: Works with any JavaScript runtime supporting Web Crypto API
- **Type Support**: Works seamlessly with both strings and Uint8Array inputs
- **Async/Await**: All operations are async for non-blocking execution
- **Zero Production Dependencies**: No external dependencies, pure Web Crypto API

## Breaking Changes in v4.0.0

- **All signing and verification functions are now async** (return Promises)
- Uses Web Crypto API instead of Node.js crypto module
- Requires `await` when calling `sign()` and `verify()` methods:

```javascript
// Before (v3.x - synchronous)
const sig = algo.sign(message, key)
const isValid = algo.verify(message, sig, key)

// After (v4.x - asynchronous)
const sig = await algo.sign(message, key)
const isValid = await algo.verify(message, sig, key)
```

## Requirements

- **Runtime**: Node.js >=18.0.0 or any environment with Web Crypto API support

## Installation

```bash
npm install jwa
```

## Usage

```javascript
import { jwa } from 'jwa'

const algo = jwa('HS256')

// Sign
const message = 'test'
const secret = 'my-secret'
const signature = await algo.sign(message, secret)

// Verify
const isValid = await algo.verify(message, signature, secret)
console.log(isValid) // true
```

## Testing

To run the tests:

```bash
npm test
```

This will validate all supported algorithms against RFC 7515 test vectors.



# Usage

## jwa(algorithm)

Creates a new `jwa` object with `sign` and `verify` methods for the
algorithm. Valid values for algorithm can be found in the table above
(`'HS256'`, `'HS384'`, etc) and are case-sensitive. Passing an invalid
algorithm value will throw a `TypeError`.


## jwa#sign(input, secretOrPrivateKey)

Sign some input with either a secret for HMAC algorithms, or a private
key for RSA and ECDSA algorithms. **Returns a Promise** that resolves to the signature.

If input is not already a string or buffer, `JSON.stringify` will be
called on it to attempt to coerce it.

For the HMAC algorithm, `secretOrPrivateKey` should be a string or a
buffer. For ECDSA and RSA, the value should be a string representing a
PEM encoded **private** key.

Output [base64url](http://en.wikipedia.org/wiki/Base64#URL_applications)
formatted. This is for convenience as JWS expects the signature in this
format. If your application needs the output in a different format,
[please open an issue](https://github.com/brianloveswords/node-jwa/issues). In
the meantime, you can use
[brianloveswords/base64url](https://github.com/brianloveswords/base64url)
to decode the signature.

As of nodejs *v0.11.8*, SPKAC support was introduce. If your nodeJs
version satisfies, then you can pass an object `{ key: '..', passphrase: '...' }`


## jwa#verify(input, signature, secretOrPublicKey)

Verify a signature. **Returns a Promise** that resolves to `true` or `false`.

`signature` should be a base64url encoded string.

For the HMAC algorithm, `secretOrPublicKey` should be a string or a
buffer. For ECDSA and RSA, the value should be a string represented a
PEM encoded **public** key.


# Example

HMAC
```js
import { jwa } from 'jwa'

const hmac = jwa('HS256')
const input = 'super important stuff'
const secret = 'shhhhhh'

const signature = await hmac.sign(input, secret)
await hmac.verify(input, signature, secret) // === true
await hmac.verify(input, signature, 'trickery!') // === false
```

With keys
```js
import { readFile } from 'node:fs/promises'
import { jwa } from 'jwa'

const privateKey = await readFile('./ecdsa-p521-private.pem', 'utf8')
const publicKey = await readFile('./ecdsa-p521-public.pem', 'utf8')

const ecdsa = jwa('ES512')
const input = 'very important stuff'

const signature = await ecdsa.sign(input, privateKey)
await ecdsa.verify(input, signature, publicKey) // === true
```
## License

MIT

```
Copyright (c) 2013 Brian J. Brennan

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
