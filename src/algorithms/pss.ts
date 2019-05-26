import { SignerFactory, VerifierFactory } from '.';
import { assertPrivateKeyHasValidType, assertPublicKeyHasValidType } from '../assertion';
import { normalizeInput } from '../normalize';
import { createSign, constants, createVerify } from 'crypto';
import { Base64 } from '../base64';

export const createPSSKeySigner: SignerFactory = bits => (thing, privateKey) => {
    assertPrivateKeyHasValidType(privateKey);
    thing = normalizeInput(thing);
    const signer = createSign('RSA-SHA' + bits);
    const sig = (signer.update(thing), signer.sign({
        key: privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST
    }, 'base64'));
    return Base64.toBase64Url(sig);
}

export const createPSSKeyVerifier: VerifierFactory = bits => (thing, signature, publicKey) => {
    assertPublicKeyHasValidType(publicKey);
    thing = normalizeInput(thing);
    signature = Base64.fromBase64Url(signature);
    const verifier = createVerify('RSA-SHA' + bits);
    verifier.update(thing);
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
