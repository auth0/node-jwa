import { SignerFactory, VerifierFactory } from '.';
import { assertPrivateKeyHasValidType, assertPublicKeyHasValidType } from '../assertion';
import { normalizeInput } from '../normalize';
import { createSign, constants, createVerify } from 'crypto';
import { Base64 } from '../base64';

export const createPSSKeySigner: SignerFactory = bits => (data, privateKey) => {
    if (privateKey === undefined) {
        throw new TypeError('Using sign with PSS requires a private key but none was given.');
    }
    assertPrivateKeyHasValidType(privateKey);
    data = normalizeInput(data);
    const signer = createSign('RSA-SHA' + bits);
    const sig = (signer.update(data), signer.sign({
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST
    }, 'base64'));
    return Base64.toBase64Url(sig);
}

export const createPSSKeyVerifier: VerifierFactory = bits => (data, signature, publicKey) => {
    if (publicKey === undefined) {
        throw new TypeError('Using verify with PSS requires a public key but none was given.');
    }
    assertPublicKeyHasValidType(publicKey);
    data = normalizeInput(data);
    signature = Base64.fromBase64Url(signature);
    const verifier = createVerify('RSA-SHA' + bits);
    verifier.update(data);
    return verifier.verify(
        {
            key: publicKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_DIGEST
        },
        signature,
        'base64'
    );
}
