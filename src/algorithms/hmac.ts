import { assertSecretKeyHasValidType } from "../assertion";
import { normalizeInput } from "../normalize";
import { createHmac, timingSafeEqual } from "crypto";
import { Base64 } from "../base64";
import { SignerFactory, VerifierFactory } from ".";

export const createHmacSigner: SignerFactory = bits => (thing, secret) => {
    assertSecretKeyHasValidType(secret);
    thing = normalizeInput(thing);
    const hmac = createHmac('sha' + bits, secret);
    const sig = (hmac.update(thing), hmac.digest('base64'))
    return Base64.toBase64Url(sig);
}

export const createHmacVerifier: VerifierFactory = bits => (thing, signature, secret) => {
    const computedSig = createHmacSigner(bits)(thing, secret.toString());
    return timingSafeEqual(Buffer.from(signature), Buffer.from(computedSig));
};
