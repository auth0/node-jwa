import { createSign, createVerify } from 'crypto';
import { SignerFactory, VerifierFactory } from ".";
import { Base64 } from '../base64';
import { assertPublicKeyHasValidType, assertPrivateKeyHasValidType } from '../assertion';
import { normalizeInput } from '../normalize';

export const createRsaSigner: SignerFactory = bits => (thing, privateKey) => {
    assertPrivateKeyHasValidType(privateKey);
    thing = normalizeInput(thing);
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = createSign(`RSA-SHA${bits}`);
    signer.update(thing);
    const sig = signer.sign(privateKey, 'base64');
    return Base64.toBase64Url(sig);
}


export const createRsaVerifier: VerifierFactory = bits => (thing, signature, publicKey) => {
    assertPublicKeyHasValidType(publicKey);
    thing = normalizeInput(thing);
    signature = Base64.fromBase64Url(signature);
    const verifier = createVerify(`RSA-SHA${bits}`);
    verifier.update(thing);
    return verifier.verify(publicKey, signature, 'base64');
};
