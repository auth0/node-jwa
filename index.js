const base64url = require('base64url');
const crypto = require('crypto');

function createHmacSigner(bits) {
  return function sign(thing, secret) {
    const hmac = crypto.createHmac('SHA' + bits, secret);
    const sig = (hmac.update(thing), hmac.digest('base64'))
    return base64url.fromBase64(sig);
  }
}

function createHmacVerifier(bits) {
  return function verify(thing, signature, secret) {
    const computedSig = createHmacSigner(bits)(thing, secret);
    return signature === computedSig;
  }
}

function createRSASigner(bits) {
  return function sign(thing, privateKey) {
    const signer = crypto.createSign('RSA-SHA' + bits);
    const sig = (signer.update(thing), signer.sign(privateKey, 'base64'));
    return base64url.fromBase64(sig);
  }
}

function createRSAVerifier(bits) {
  return function verify(thing, signature, publicKey) {
    signature = base64url.toBase64(signature);
    const verifier = crypto.createVerify('RSA-SHA' + bits);
    verifier.update(thing);
    return verifier.verify(publicKey, signature, 'base64');
  }
}

function createNoneSigner() {
  return function sign() {
    return '';
  }
}

function createNoneVerifier() {
  return function verify(thing, signature) {
    return signature === '';
  }
}

module.exports = function jwa(algorithm) {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createRSASigner,
    none: createNoneSigner,
  }
  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createRSAVerifier,
    none: createNoneVerifier,
  }
  const match = algorithm.match(/(RS|ES|HS|none)(256|384|512)?/i);
  const algo = match[1].toLowerCase();
  const bits = match[2];

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  }
};