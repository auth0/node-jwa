import { createSign, createVerify } from 'crypto';
import { SignerFactory, VerifierFactory } from ".";
import { Base64 } from '../base64';
import { assertPublicKeyHasValidType, assertPrivateKeyHasValidType } from '../assertion';
import { normalizeInput } from '../normalize';

export const createRsaSigner: SignerFactory = bits => (data, privateKey) => {
    if(privateKey === undefined) {
        throw new TypeError('Using sign with RSA requires a private key but none was given.');
    }
    assertPrivateKeyHasValidType(privateKey);
    data = normalizeInput(data);
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = createSign(`RSA-SHA${bits}`);
    signer.update(data);
    const sig = signer.sign(privateKey, 'base64');
    return Base64.toBase64Url(sig);
}


export const createRsaVerifier: VerifierFactory = bits => (data, signature, publicKey) => {
    if(publicKey === undefined) {
        throw new TypeError('Using verify with RSA requires a public key but none was given.');
    }
    assertPublicKeyHasValidType(publicKey);
    data = normalizeInput(data);
    signature = Base64.fromBase64Url(signature);
    const verifier = createVerify(`RSA-SHA${bits}`);
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'base64');
};
