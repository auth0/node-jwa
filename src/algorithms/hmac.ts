import { assertSecretKeyHasValidType } from "../assertion";
import { normalizeInput } from "../normalize";
import { createHmac, timingSafeEqual } from "crypto";
import { Base64 } from "../base64";
import { SignerFactory, VerifierFactory } from ".";

export const createHmacSigner: SignerFactory = bits => (data, secret) => {
    if (secret === undefined) {
        throw new TypeError('Using sign with HMAC requires a secret key but none was given.');
    }
    assertSecretKeyHasValidType(secret);
    data = normalizeInput(data);
    const hmac = createHmac(`SHA${bits}`, secret);
    const sig = (hmac.update(data), hmac.digest('base64'))
    return Base64.toBase64Url(sig);
}

export const createHmacVerifier: VerifierFactory = bits => (data, signature, secret) => {
    if (secret === undefined) {
        throw new TypeError('Using verify with HMAC requires a secret key but none was given.');
    }
    assertSecretKeyHasValidType(secret);
    const computedSig = createHmacSigner(bits)(data, secret as any); // TODO: Check for TypedArrays and Views
    return timingSafeEqual(Buffer.from(signature), Buffer.from(computedSig));
};
