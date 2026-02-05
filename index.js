/** Error message template for invalid algorithms */
const MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'

/** Error message for invalid verifier key */
const MSG_INVALID_VERIFIER_KEY = 'key must be a string or Uint8Array'

/** Error message for invalid signer key */
const MSG_INVALID_SIGNER_KEY = 'key must be a string or Uint8Array'

/** Web Crypto API instance */
const { crypto } = globalThis

/**
 * Converts a DER-encoded ECDSA signature to JOSE format (r || s)
 * Web Crypto API returns DER-encoded signatures, but JWS expects raw r||s format
 * @param {Uint8Array} derBytes - DER-encoded signature bytes
 * @param {string} algorithm - Algorithm name (ES256, ES384, or ES512)
 * @returns JOSE-formatted signature (r || s)
 * @throws {Error} If DER encoding is invalid
 */
function derToJose(derBytes, algorithm) {
  const componentLength = algorithm === 'ES256' ? 32 : algorithm === 'ES384' ? 48 : 66

  let offset = 0

  // SEQUENCE tag
  if (derBytes[offset] !== 0x30) throw new Error('Invalid DER encoding')
  offset++

  // Skip SEQUENCE length
  const seqLength = derBytes[offset]
  offset++
  if (seqLength > 127) {
    const lengthBytes = seqLength & 0x7f
    offset += lengthBytes
  }

  // Parse r
  if (derBytes[offset] !== 0x02) throw new Error('Invalid DER encoding for r')
  offset++
  const rLength = derBytes[offset]
  offset++
  const rBytes = derBytes.slice(offset, offset + rLength)
  offset += rLength

  // Parse s
  if (derBytes[offset] !== 0x02) throw new Error('Invalid DER encoding for s')
  offset++
  const sLength = derBytes[offset]
  offset++
  const sBytes = derBytes.slice(offset, offset + sLength)

  // Pad r and s to component length and concatenate
  const r = new Uint8Array(componentLength)
  const s = new Uint8Array(componentLength)

  r.set(rBytes, componentLength - rLength)
  s.set(sBytes, componentLength - sLength)

  const result = new Uint8Array(componentLength * 2)
  result.set(r)
  result.set(s, componentLength)

  return result
}

/** Checks if a value is a Uint8Array instance */
function isUint8Array(obj) {
  return obj instanceof Uint8Array
}

/**
 * Converts a string to a Uint8Array using UTF-8 encoding
 * If input is already a Uint8Array, it is returned as-is
 * @param {string|Uint8Array} str - Input string or bytes
 * @returns UTF-8 encoded bytes of the input string, or original Uint8Array
 */
function stringToUint8Array(str) {
  if (typeof str === 'string') {
    return new TextEncoder().encode(str)
  }
  return str
}

/**
 * @type {(arr: Uint8Array) => string}
 */
const uint8ArrayToBase64Url = (() => {
  if (typeof Uint8Array.prototype.toBase64 === 'function') {
    return (arr) => arr.toBase64({ alphabet: 'base64url', omitPadding: true })
  }
  // Fallback for older environments
  return (arr) => {
    let binary = ''
    const len = arr.byteLength
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(arr[i])
    }
    return btoa(binary)
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
  }
})()

/**
 * Converts a base64url-encoded string to a Uint8Array
 * @type {(str: string) => Uint8Array}
 */
const base64UrlToUint8Array = (() => {
  if (typeof Uint8Array.fromBase64 === 'function') {
    return (str) => Uint8Array.fromBase64(str, { alphabet: 'base64url' })
  }
  // Fallback for older environments
  return (str) => {
    const base64 = str
      .replace(/\-/g, '+')
      .replace(/_/g, '/')
    const padding = 4 - (base64.length % 4)
    const padded = padding !== 4 ? base64 + '='.repeat(padding) : base64
    const binary = atob(padded)
    const arr = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      arr[i] = binary.charCodeAt(i)
    }
    return arr
  }
})()

/**
 * Parses a PEM-encoded key and extracts the PKCS8 bytes
 * @param {string} pem - PEM-encoded private or public key
 * @returns Raw PKCS8 bytes from the PEM file
 */
function parsePemBytes(pem) {
  const lines = pem.split('\n')
  let keyData = ''
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].includes('-----')) break
    keyData += lines[i]
  }

  const binaryString = atob(keyData)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes
}

/**
 * Normalizes input to a string or Uint8Array
 * If input is neither, it is JSON stringified
 * @param {*} thing - Input to normalize
 * @returns {string|Uint8Array} Normalized input
 */
function normalizeInput(thing) {
  if (typeof thing === 'string' || isUint8Array(thing)) {
    return thing
  }
  return JSON.stringify(thing)
}

/**
 * Creates an HMAC signer function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async sign function that takes (input, secret)
 */
function createHmacSigner(bits) {
  /**
   * Signs the input using HMAC with the provided secret
   * @param {string|Uint8Array} thing - Input to sign (string or bytes)
   * @param {string|Uint8Array} secret - Secret key for HMAC (string or bytes)
   * @returns Base64url-encoded signature
   * @throws {TypeError} If secret is not a string or Uint8Array
   */
  return async function sign(thing, secret) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)
    const secretData = stringToUint8Array(secret)

    const key = await crypto.subtle.importKey(
      'raw',
      secretData,
      { name: 'HMAC', hash: `SHA-${bits}` },
      false,
      ['sign']
    )

    const signature = await crypto.subtle.sign('HMAC', key, data)
    return uint8ArrayToBase64Url(new Uint8Array(signature))
  }
}

/**
 * Creates an HMAC verifier function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async verify function that takes (input, signature, secret)
 */
function createHmacVerifier(bits) {
  /**
   * Verifies the HMAC signature of the input using the provided secret
   * @param {string|Uint8Array} thing - Input to verify (string or bytes)
   * @param {string} signature - Base64url-encoded signature to verify
   * @param {string|Uint8Array} secret - Secret key for HMAC (string or bytes)
   * @returns True if signature is valid, false otherwise
   * @throws {TypeError} If secret is not a string or Uint8Array
   */
  return async function verify(thing, signature, secret) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)
    const secretData = stringToUint8Array(secret)
    const sigBytes = base64UrlToUint8Array(signature)

    const key = await crypto.subtle.importKey(
      'raw',
      secretData,
      { name: 'HMAC', hash: `SHA-${bits}` },
      false,
      ['verify']
    )

    return crypto.subtle.verify('HMAC', key, sigBytes, data)
  }
}

/**
 * Creates an RSA PKCS#1 v1.5 signer function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async sign function that takes (input, privateKey)
 */
function createKeySigner(bits) {
  /**
   * Signs the input using RSA PKCS#1 v1.5 with the provided private key
   * @param {string|Uint8Array} thing - Input to sign (string or bytes)
   * @param {string|Uint8Array|CryptoKey} privateKey - PEM string, raw bytes, or CryptoKey for signing
   * @returns Base64url-encoded signature
   * @throws {TypeError} If privateKey is not a string, Uint8Array, or CryptoKey
   */
  return async function sign(thing, privateKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)

    let key
    if (typeof privateKey === 'string') {
      const bytes = parsePemBytes(privateKey)
      key = await crypto.subtle.importKey(
        'pkcs8',
        bytes,
        { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
        false,
        ['sign']
      )
    } else if (privateKey instanceof CryptoKey) {
      key = privateKey
    } else if (isUint8Array(privateKey)) {
      key = await crypto.subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
        false,
        ['sign']
      )
    } else {
      throw new TypeError(MSG_INVALID_SIGNER_KEY)
    }

    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      data
    )
    return uint8ArrayToBase64Url(new Uint8Array(signature))
  }
}

/**
 * Creates an RSA PKCS#1 v1.5 verifier function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async verify function that takes (input, signature, publicKey)
 */
function createKeyVerifier(bits) {
  /**
   * Verifies the RSA PKCS#1 v1.5 signature of the input using the provided public key
   * @param {string|Uint8Array} thing - Input to verify (string or bytes)
   * @param {string} signature - Base64url-encoded signature to verify
   * @param {string|Uint8Array|CryptoKey} publicKey - PEM string, raw bytes, or CryptoKey for verification
   * @returns True if signature is valid, false otherwise
   * @throws {TypeError} If publicKey is not a string, Uint8Array, or CryptoKey
   */
  return async function verify(thing, signature, publicKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)
    const sigBytes = base64UrlToUint8Array(signature)

    let key
    if (typeof publicKey === 'string') {
      const bytes = parsePemBytes(publicKey)
      key = await crypto.subtle.importKey(
        'spki',
        bytes,
        { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
        false,
        ['verify']
      )
    } else if (publicKey instanceof CryptoKey) {
      key = publicKey
    } else if (isUint8Array(publicKey)) {
      key = await crypto.subtle.importKey(
        'spki',
        publicKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
        false,
        ['verify']
      )
    } else {
      throw new TypeError(MSG_INVALID_VERIFIER_KEY)
    }

    return crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      sigBytes,
      data
    )
  }
}

/**
 * Creates an RSA-PSS signer function for the specified bit depth
 * Salt length is set to hash output length per PSS specification
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async sign function that takes (input, privateKey)
 */
function createPSSKeySigner(bits) {
  const saltLength = parseInt(bits) / 8

  /**
   * Signs the input using RSA-PSS with the provided private key
   * @param {string|Uint8Array} thing - Input to sign (string or bytes)
   * @param {string|Uint8Array|CryptoKey} privateKey - PEM string, raw bytes, or CryptoKey for signing
   * @return Base64url-encoded signature
   */
  return async function sign(thing, privateKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)

    let key
    if (typeof privateKey === 'string') {
      const bytes = parsePemBytes(privateKey)
      key = await crypto.subtle.importKey(
        'pkcs8',
        bytes,
        { name: 'RSA-PSS', hash: `SHA-${bits}` },
        false,
        ['sign']
      )
    } else if (privateKey instanceof CryptoKey) {
      key = privateKey
    } else if (isUint8Array(privateKey)) {
      key = await crypto.subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'RSA-PSS', hash: `SHA-${bits}` },
        false,
        ['sign']
      )
    } else {
      throw new TypeError(MSG_INVALID_SIGNER_KEY)
    }

    const signature = await crypto.subtle.sign(
      { name: 'RSA-PSS', saltLength },
      key,
      data
    )
    return uint8ArrayToBase64Url(new Uint8Array(signature))
  }
}

/**
 * Creates an RSA-PSS verifier function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512)
 * @returns Async verify function that takes (input, signature, publicKey)
 */
function createPSSKeyVerifier(bits) {
  const saltLength = parseInt(bits) / 8

  /**
   * Verifies the RSA-PSS signature of the input using the provided public key
   * @param {string|Uint8Array} thing - Input to verify (string or bytes)
   * @param {string} signature - Base64url-encoded signature to verify
   * @param {string|Uint8Array|CryptoKey} publicKey - PEM string, raw bytes, or CryptoKey for verification
   * @returns True if signature is valid, false otherwise
   * @throws {TypeError} If publicKey is not a string, Uint8Array, or CryptoKey
   */
  return async function verify(thing, signature, publicKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)
    const sigBytes = base64UrlToUint8Array(signature)

    let key
    if (typeof publicKey === 'string') {
      const bytes = parsePemBytes(publicKey)
      key = await crypto.subtle.importKey(
        'spki',
        bytes,
        { name: 'RSA-PSS', hash: `SHA-${bits}` },
        false,
        ['verify']
      )
    } else if (publicKey instanceof CryptoKey) {
      key = publicKey
    } else if (isUint8Array(publicKey)) {
      key = await crypto.subtle.importKey(
        'spki',
        publicKey,
        { name: 'RSA-PSS', hash: `SHA-${bits}` },
        false,
        ['verify']
      )
    } else {
      throw new TypeError(MSG_INVALID_VERIFIER_KEY)
    }

    return crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength },
      key,
      sigBytes,
      data
    )
  }
}

/**
 * Creates an ECDSA signer function for the specified bit depth
 * Converts DER-encoded signatures to JOSE format (r || s)
 * @param {number} bits - SHA bit depth (256, 384, or 512) corresponding to curve (P-256, P-384, P-521)
 * @returns Async sign function that takes (input, privateKey)
 */
function createECDSASigner(bits) {
  const namedCurve = bits === '256' ? 'P-256' : bits === '384' ? 'P-384' : 'P-521'

  /**
   * Signs the input using ECDSA with the provided private key
   * @param {string|Uint8Array} thing - Input to sign (string or bytes)
   * @param {string|Uint8Array|CryptoKey} privateKey - PEM string, raw bytes, or CryptoKey for signing
   * @returns Base64url-encoded signature in JOSE format (r || s)
   * @throws {TypeError} If privateKey is not a string, Uint8Array, or CryptoKey
   */
  return async function sign(thing, privateKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)

    let key
    if (typeof privateKey === 'string') {
      const bytes = parsePemBytes(privateKey)
      key = await crypto.subtle.importKey(
        'pkcs8',
        bytes,
        { name: 'ECDSA', namedCurve },
        false,
        ['sign']
      )
    } else if (privateKey instanceof CryptoKey) {
      key = privateKey
    } else if (isUint8Array(privateKey)) {
      key = await crypto.subtle.importKey(
        'pkcs8',
        privateKey,
        { name: 'ECDSA', namedCurve },
        false,
        ['sign']
      )
    } else {
      throw new TypeError(MSG_INVALID_SIGNER_KEY)
    }

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: `SHA-${bits}` },
      key,
      data
    )
    const joseSignature = derToJose(new Uint8Array(signature), `ES${bits}`)
    return uint8ArrayToBase64Url(joseSignature)
  }
}

/**
 * Creates an ECDSA verifier function for the specified bit depth
 * @param {number} bits - SHA bit depth (256, 384, or 512) corresponding to curve (P-256, P-384, P-521)
 * @returns Async verify function that takes (input, signature, publicKey)
 */
function createECDSAVerifer(bits) {
  const namedCurve = bits === '256' ? 'P-256' : bits === '384' ? 'P-384' : 'P-521'
  /**
   * Verifies the ECDSA signature of the input using the provided public key
   * @param {string|Uint8Array} thing - Input to verify (string or bytes)
   * @param {string} signature - Base64url-encoded signature to verify
   * @param {string|Uint8Array|CryptoKey} publicKey - PEM string, raw bytes, or CryptoKey for verification
   * @returns True if signature is valid, false otherwise
   * @throws {TypeError} If publicKey is not a string, Uint8Array, or CryptoKey
   */
  return async function verify(thing, signature, publicKey) {
    thing = normalizeInput(thing)
    const data = stringToUint8Array(thing)
    // The signature in JOSE format is already in raw r||s format (base64url)
    // Web Crypto.verify() expects raw bytes, not DER
    const joseBytes = base64UrlToUint8Array(signature)

    let key
    if (typeof publicKey === 'string') {
      const bytes = parsePemBytes(publicKey)
      key = await crypto.subtle.importKey(
        'spki',
        bytes,
        { name: 'ECDSA', namedCurve },
        false,
        ['verify']
      )
    } else if (publicKey instanceof CryptoKey) {
      key = publicKey
    } else if (isUint8Array(publicKey)) {
      key = await crypto.subtle.importKey(
        'spki',
        publicKey,
        { name: 'ECDSA', namedCurve },
        false,
        ['verify']
      )
    } else {
      throw new TypeError(MSG_INVALID_VERIFIER_KEY)
    }

    return crypto.subtle.verify(
      { name: 'ECDSA', hash: `SHA-${bits}` },
      key,
      joseBytes,
      data
    )
  }
}

/**
 * Creates a signer for the 'none' algorithm (unsigned tokens)
 * @returns Async sign function that always returns empty string
 */
function createNoneSigner() {
  return async function sign() {
    return ''
  }
}

/**
 * Creates a verifier for the 'none' algorithm (unsigned tokens)
 * @returns Async verify function that checks if signature is empty
 */
function createNoneVerifier() {
  return async function verify(thing, signature) {
    return signature === ''
  }
}

/**
 * Creates a JWA algorithm instance with sign and verify methods
 * Uses Web Crypto API for all cryptographic operations
 *
 * Supported algorithms:
 * - HMAC: HS256, HS384, HS512
 * - RSA: RS256, RS384, RS512
 * - RSA-PSS: PS256, PS384, PS512
 * - ECDSA: ES256, ES384, ES512
 * - Unsigned: none
 *
 * @param {string} algorithm - JWS algorithm identifier (case-sensitive)
 * @returns {Object} Object with async sign and verify methods
 * @returns Async function(input, secretOrPrivateKey) => Promise<string> returns.sign
 * @returns {Function} returns.verify - Async function(input, signature, secretOrPublicKey) => Promise<boolean>
 * @throws {TypeError} If algorithm is not recognized
 *
 * @example
 * // HMAC signing
 * const algo = jwa('HS256')
 * const sig = await algo.sign('message', 'secret')
 * const isValid = await algo.verify('message', sig, 'secret')
 *
 * @example
 * // RSA signing with PEM-encoded key
 * const algo = jwa('RS256')
 * const privateKey = `-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----`
 * const sig = await algo.sign('message', privateKey)
 */
function jwa(algorithm) {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner,
  }
  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier,
  }
  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/)
  if (!match)
    throw new TypeError(MSG_INVALID_ALGORITHM, algorithm)
  const algo = (match[1] || match[3]).toLowerCase()
  const bits = match[2]

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  }
}

export {
  jwa
}
