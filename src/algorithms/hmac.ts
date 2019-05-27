import { assertSecretKeyHasValidType } from "../assertion";
import { normalizeInput } from "../normalize";
import { createHmac, timingSafeEqual } from "crypto";
import { Base64 } from "../base64";
import { SignerFactory, VerifierFactory } from ".";

export const createHmacSigner: SignerFactory = bits => (data, secret) => {
    if (secret === undefined) {
        throw new TypeError('Using sign with HMAC requires a private key but none was given.');
    }
    assertSecretKeyHasValidType(secret);
    data = normalizeInput(data);
    const hmac = createHmac('sha' + bits, secret);
    const sig = (hmac.update(data), hmac.digest('base64'))
    return Base64.toBase64Url(sig);
}

export const createHmacVerifier: VerifierFactory = bits => (data, signature, secret) => {
    if (secret === undefined) {
        throw new TypeError('Using verify with HMAC requires a public key but none was given.');
    }
    const computedSig = createHmacSigner(bits)(data, secret.toString());
    return timingSafeEqual(Buffer.from(signature), Buffer.from(computedSig));
};
