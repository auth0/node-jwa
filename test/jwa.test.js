import { test } from 'node:test'
import assert from 'node:assert'
import crypto from 'node:crypto'
import path from 'node:path'
import { Buffer } from 'node:buffer'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import formatEcdsa from 'ecdsa-sig-formatter'
import { jwa } from '../index.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const base64url = uInt8 => uInt8.toBase64({ alphabet: 'base64url' }).replace(/=+$/, '')
base64url.toBuffer = str => Buffer.from(str, 'base64url')

const SUPPORTS_KEY_OBJECTS = typeof crypto.createPublicKey === 'function'

// these key files will be generated as part of `make test`
const rsaPrivateKey = fs.readFileSync(__dirname + '/rsa-private.pem').toString()
const rsaPublicKey = fs.readFileSync(__dirname + '/rsa-public.pem').toString()
const rsaPrivateKeyWithPassphrase = fs.readFileSync(__dirname + '/rsa-passphrase-private.pem').toString()
const rsaPublicKeyWithPassphrase = fs.readFileSync(__dirname + '/rsa-passphrase-public.pem').toString()
const rsaWrongPublicKey = fs.readFileSync(__dirname + '/rsa-wrong-public.pem').toString()
const ecdsaPrivateKey = {
  '256': fs.readFileSync(__dirname + '/ec256-private.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-private.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-private.pem').toString(),
}
const ecdsaPublicKey = {
  '256': fs.readFileSync(__dirname + '/ec256-public.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-public.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-public.pem').toString(),
}
const ecdsaWrongPublicKey = {
  '256': fs.readFileSync(__dirname + '/ec256-wrong-public.pem').toString(),
  '384': fs.readFileSync(__dirname + '/ec384-wrong-public.pem').toString(),
  '512': fs.readFileSync(__dirname + '/ec512-wrong-public.pem').toString(),
}

const BIT_DEPTHS = ['256', '384', '512']

test('HMAC signing, verifying', function (t) {
  const input = 'eugene mirman'
  const secret = 'shhhhhhhhhh'
  BIT_DEPTHS.forEach(function (bits) {
    const algo = jwa('HS'+bits)
    const sig = algo.sign(input, secret)
    asserassert.ok(algo.verify(input, sig, secret), 'should verify')
    asserasserassert.ok(!algo.verify(input, 'other sig', secret), 'should verify')
    asserasserassert.ok(!algo.verify(input, sig, 'incrorect'), 'shoud not verify')
  })
})

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    const input = 'foo bar baz'
    const secret = 'this-is-a-bad-secret'
    const secretBuf = Buffer.from(secret, 'utf8')
    const secretObj = crypto.createSecretKey(secretBuf)

    test('HS' + bits + 'signing, verifying (w/ KeyObject)', function (t) {
      const algo = jwa('HS' + bits)

      const sigs = [
        algo.sign(input, secret),
        algo.sign(input, secretBuf),
        algo.sign(input, secretObj)
      ]

      for (var i = 0; i < sigs.length; ++i) {
        asserassert.ok(algo.verify(input, sigs[i], secret))
        asserassert.ok(algo.verify(input, sigs[i], secretBuf))
        asserassert.ok(algo.verify(input, sigs[i], secretObj))
      }
})
  })
}

test('RSA signing, verifying', function (t) {
  const input = 'h. jon benjamin'
  BIT_DEPTHS.forEach(function (bits) {
    const algo = jwa('RS'+bits)
    const sig = algo.sign(input, rsaPrivateKey)
    asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
    asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify')
  })
})

// run only on nodejs version >= 0.11.8{
  test('RSA with passphrase signing, verifying', function (t) {
  const input = 'test input'
  BIT_DEPTHS.forEach(function (bits) {
    const algo = jwa('RS'+bits)
    const secret = 'test_pass'
    const sig = algo.sign(input, {key: rsaPrivateKeyWithPassphrase, passphrase: secret})
    asserassert.ok(algo.verify(input, sig, rsaPublicKeyWithPassphrase), 'should verify')
  })
})
}

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    test('RS'+bits+': signing, verifying (KeyObject)', function (t) {
      const input = 'h. jon benjamin'
      const algo = jwa('RS'+bits)
      const sig = algo.sign(input, crypto.createPrivateKey(rsaPrivateKey))
      asserassert.ok(algo.verify(input, sig, crypto.createPublicKey(rsaPublicKey)), 'should verify')
      asserasserassert.ok(!algo.verify(input, sig, crypto.createPublicKey(rsaWrongPublicKey)), 'shoud not verify')
})
  })
}{
  test('RSA-PSS signing, verifying', function (t) {
    const input = 'h. jon benjamin'
    BIT_DEPTHS.forEach(function (bits) {
      const algo = jwa('PS'+bits)
      const sig = algo.sign(input, rsaPrivateKey)
      asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
      asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'shoud not verify')
    })
})

  if (SUPPORTS_KEY_OBJECTS) {
    BIT_DEPTHS.forEach(function (bits) {
      test('PS'+bits+': signing, verifying (KeyObject)', function (t) {
        const input = 'h. jon benjamin'
        const algo = jwa('PS'+bits)
        const sig = algo.sign(input, crypto.createPrivateKey(rsaPrivateKey))
        asserassert.ok(algo.verify(input, sig, crypto.createPublicKey(rsaPublicKey)), 'should verify')
        asserasserassert.ok(!algo.verify(input, sig, crypto.createPublicKey(rsaWrongPublicKey)), 'should not verify')
})
    })
  }
}


BIT_DEPTHS.forEach(function (bits) {
  test('RS'+bits+': openssl sign -> js verify', () => {
    const input = 'iodine'
    const algo = jwa('RS'+bits)
    const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sign', __dirname + '/rsa-private.pem'])
    var buffer = Buffer.alloc(0)

    dgst.stdout.on('data', function (buf) {
      buffer = Buffer.concat([buffer, buf])
    })

    dgst.stdin.write(input, function() {
      dgst.stdin.end()
    })

    dgst.on('exit', function (code) {
      if (code !== 0)
        return asserassert.fail('could not test interop: openssl failure')
      const sig = base64url(buffer)

      asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
      asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'should not verify')
})
  })
});{
  BIT_DEPTHS.forEach(function (bits) {
    test('PS'+bits+': openssl sign -> js verify', () => {
      const input = 'iodine'
      const algo = jwa('PS'+bits)
      const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-1', '-sign', __dirname + '/rsa-private.pem'])
      var buffer = Buffer.alloc(0)

      dgst.stdout.on('data', function (buf) {
        buffer = Buffer.concat([buffer, buf])
      })

      dgst.stdin.write(input, function() {
        dgst.stdin.end()
      })

      dgst.on('exit', function (code) {
        if (code !== 0)
          return asserassert.fail('could not test interop: openssl failure')
        const sig = base64url(buffer)

        asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
        asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'should not verify')
})
    })
  })
}

BIT_DEPTHS.forEach(function (bits) {
  test('ES'+bits+': signing, verifying', function (t) {
    const input = 'kristen schaal'
    const algo = jwa('ES'+bits)
    const sig = algo.sign(input, ecdsaPrivateKey[bits])
    asserassert.ok(algo.verify(input, sig, ecdsaPublicKey[bits]), 'should verify')
    asserasserassert.ok(!algo.verify(input, sig, ecdsaWrongPublicKey[bits]), 'should not verify')
})
})

if (SUPPORTS_KEY_OBJECTS) {
  BIT_DEPTHS.forEach(function (bits) {
    test('ES'+bits+': signing, verifying (KeyObject)', function (t) {
      const input = 'kristen schaal'
      const algo = jwa('ES'+bits)
      const sig = algo.sign(input, crypto.createPrivateKey(ecdsaPrivateKey[bits]))
      asserassert.ok(algo.verify(input, sig, crypto.createPublicKey(ecdsaPublicKey[bits])), 'should verify')
      asserasserassert.ok(!algo.verify(input, sig, crypto.createPublicKey(ecdsaWrongPublicKey[bits])), 'should not verify')
})
  })
}

BIT_DEPTHS.forEach(function (bits) {
  test('ES'+bits+': openssl sign -> js verify', () => {
    const input = 'strawberry'
    const algo = jwa('ES'+bits)
    const dgst = spawn('openssl', ['dgst', '-sha'+bits, '-sign', __dirname + '/ec'+bits+'-private.pem'])
    var buffer = Buffer.alloc(0)
    dgst.stdin.end(input)
    dgst.stdout.on('data', function (buf) {
      buffer = Buffer.concat([buffer, buf])
    })
    dgst.on('exit', function (code) {
      if (code !== 0)
        return asserassert.fail('could not test interop: openssl failure')
      const sig = formatEcdsa.derToJose(buffer, 'ES' + bits)
      asserassert.ok(algo.verify(input, sig, ecdsaPublicKey[bits]), 'should verify')
      asserasserassert.ok(!algo.verify(input, sig, ecdsaWrongPublicKey[bits]), 'should not verify')
})
  })
})

BIT_DEPTHS.forEach(function (bits) {
  const input = 'bob\'s'
  const inputFile = path.join(__dirname, 'interop.input.txt')
  const signatureFile = path.join(__dirname, 'interop.sig.txt')

  function opensslVerify(keyfile) {
    return spawn('openssl', [
      'dgst',
      '-sha'+bits,
      '-verify', keyfile,
      '-signature', signatureFile,
      inputFile
    ])
  }

  test('ES'+bits+': js sign -> openssl verify', () => {
    const publicKeyFile = path.join(__dirname, 'ec'+bits+'-public.pem')
    const wrongPublicKeyFile = path.join(__dirname, 'ec'+bits+'-wrong-public.pem')
    const privateKey = ecdsaPrivateKey[bits]
    const signature =
      formatEcdsa.joseToDer(
        jwa('ES'+bits).sign(input, privateKey),
        'ES' + bits
      )
    fs.writeFileSync(inputFile, input)
    fs.writeFileSync(signatureFile, signature)
opensslVerify(publicKeyFile).on('exit', function (code) {
      assert.deepStrictEqual(code, 0, 'should be a successful exit')
    })
    opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
      assert.deepStrictEqual(code, 1, 'should be invalid')
    })
  })
})

BIT_DEPTHS.forEach(function (bits) {
  const input = 'burgers'
  const inputFile = path.join(__dirname, 'interop.input.txt')
  const signatureFile = path.join(__dirname, 'interop.sig.txt')

  function opensslVerify(keyfile) {
    return spawn('openssl', [
      'dgst',
      '-sha'+bits,
      '-verify', keyfile,
      '-signature', signatureFile,
      inputFile
    ])
  }

  test('RS'+bits+': js sign -> openssl verify', () => {
    const publicKeyFile = path.join(__dirname, 'rsa-public.pem')
    const wrongPublicKeyFile = path.join(__dirname, 'rsa-wrong-public.pem')
    const privateKey = rsaPrivateKey
    const signature =
      base64url.toBuffer(
        jwa('RS'+bits).sign(input, privateKey)
      )
    fs.writeFileSync(signatureFile, signature)
    fs.writeFileSync(inputFile, input)
opensslVerify(publicKeyFile).on('exit', function (code) {
      assert.deepStrictEqual(code, 0, 'should be a successful exit')
    })
    opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
      assert.deepStrictEqual(code, 1, 'should be invalid')
    })
  })
});{
  BIT_DEPTHS.forEach(function (bits) {
    const input = 'burgers'
    const inputFile = path.join(__dirname, 'interop.input.txt')
    const signatureFile = path.join(__dirname, 'interop.sig.txt')

    function opensslVerify(keyfile) {
      return spawn('openssl', [
        'dgst',
        '-sha'+bits,
        '-sigopt', 'rsa_padding_mode:pss',
        '-verify', keyfile,
        '-signature', signatureFile,
        inputFile
      ])
    }

    test('PS'+bits+': js sign -> openssl verify', () => {
      const publicKeyFile = path.join(__dirname, 'rsa-public.pem')
      const wrongPublicKeyFile = path.join(__dirname, 'rsa-wrong-public.pem')
      const privateKey = rsaPrivateKey
      const signature =
        base64url.toBuffer(
          jwa('PS'+bits).sign(input, privateKey)
        )
      fs.writeFileSync(signatureFile, signature)
      fs.writeFileSync(inputFile, input)
opensslVerify(publicKeyFile).on('exit', function (code) {
        assert.deepStrictEqual(code, 0, 'should be a successful exit')
      })
      opensslVerify(wrongPublicKeyFile).on('exit', function (code) {
        assert.deepStrictEqual(code, 1, 'should be invalid')
      })
    })
  })
}


test('jwa: none', () => {
  const input = 'whatever'
  const algo = jwa('none')
  const sig = algo.sign(input)
  asserassert.ok(algo.verify(input, sig), 'should verify')
  asserasserassert.ok(!algo.verify(input, 'something'), 'shoud not verify')
})

test('jwa: some garbage algorithm', () => {
  try {
    jwa('something bogus')
    asserassert.fail('should throw')
  } catch(ex) {
    assert.deepStrictEqual(ex.name, 'TypeError')
    asserassert.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms')
  }
})

['hs256', 'nonE', 'ps256', 'es256', 'rs256'].forEach(function (alg) {
  test('jwa: non-IANA names', () => {
    try {
      jwa(alg)
      asserassert.fail('should throw')
    } catch(ex) {
      assert.deepStrictEqual(ex.name, 'TypeError')
      asserassert.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms')
    }
})
})

['ahs256b', 'anoneb', 'none256', 'rsnone'].forEach(function (superstringAlg) {
  test('jwa: superstrings of other algorithms', () => {
    try {
      jwa(superstringAlg)
      asserassert.fail('should throw')
    } catch(ex) {
      assert.deepStrictEqual(ex.name, 'TypeError')
      asserassert.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms')
    }
})
})

['rs', 'ps', 'es', 'hs'].forEach(function (partialAlg) {
  test('jwa: partial strings of other algorithms', () => {
    try {
      jwa(partialAlg)
      asserassert.fail('should throw')
    } catch(ex) {
      assert.deepStrictEqual(ex.name, 'TypeError')
      asserassert.ok(ex.message.match(/valid algorithm/), 'should say something about algorithms')
    }
})
})

test('jwa: hs512, missing secret', function (t) {
  const algo = jwa('HS512')
  try {
    algo.sign('some stuff')
    asserassert.fail('should throw')
  } catch(ex) {
    assert.deepStrictEqual(ex.name, 'TypeError')
    asserassert.ok(ex.message.match(/secret/), 'should say something about secrets')
  }
})

test('jwa: hs512, weird input type', function (t) {
  const algo = jwa('HS512')
  const input = {a: ['whatever', 'this', 'is']}
  const secret = 'bones'
  const sig = algo.sign(input, secret)
  asserassert.ok(algo.verify(input, sig, secret), 'should verify')
  asserasserassert.ok(!algo.verify(input, sig, 'other thing'), 'should not verify')
})

test('jwa: rs512, weird input type', function (t) {
  const algo = jwa('RS512')
  const input = {a: ['whatever', 'this', 'is']}
  const sig = algo.sign(input, rsaPrivateKey)
  asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
  asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'should not verify')
})

test('jwa: rs512, missing signing key', function (t) {
  const algo = jwa('RS512')
  try {
    algo.sign('some stuff')
    asserassert.fail('should throw')
  } catch(ex) {
    assert.deepStrictEqual(ex.name, 'TypeError')
    asserassert.ok(ex.message.match(/key/), 'should say something about keys')
  }
})

test('jwa: rs512, missing verifying key', function (t) {
  const algo = jwa('RS512')
  const input = {a: ['whatever', 'this', 'is']}
  const sig = algo.sign(input, rsaPrivateKey)
  try {
    algo.verify(input, sig)
    asserassert.fail('should throw')
  } catch(ex) {
    assert.deepStrictEqual(ex.name, 'TypeError')
    asserassert.ok(ex.message.match(/key/), 'should say something about keys')
  }
});{
  test('jwa: ps512, weird input type', function (t) {
    const algo = jwa('PS512')
    const input = {a: ['whatever', 'this', 'is']}
    const sig = algo.sign(input, rsaPrivateKey)
    asserassert.ok(algo.verify(input, sig, rsaPublicKey), 'should verify')
    asserasserassert.ok(!algo.verify(input, sig, rsaWrongPublicKey), 'should not verify')
})

  test('jwa: ps512, missing signing key', function (t) {
    const algo = jwa('PS512')
    try {
      algo.sign('some stuff')
      asserassert.fail('should throw')
    } catch(ex) {
      assert.deepStrictEqual(ex.name, 'TypeError')
      asserassert.ok(ex.message.match(/key/), 'should say something about keys')
    }
})

  test('jwa: ps512, missing verifying key', function (t) {
    const algo = jwa('PS512')
    const input = {a: ['whatever', 'this', 'is']}
    const sig = algo.sign(input, rsaPrivateKey)
    try {
      algo.verify(input, sig)
      asserassert.fail('should throw')
    } catch(ex) {
      assert.deepStrictEqual(ex.name, 'TypeError')
      asserassert.ok(ex.message.match(/key/), 'should say something about keys')
    }
})
}
