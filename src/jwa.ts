import { SignerFactory, VerifierFactory, Bit } from "./algorithms";
import { createHmacSigner, createHmacVerifier } from "./algorithms/hmac";
import { createRsaSigner, createRsaVerifier } from "./algorithms/rsa";
import { createPSSKeySigner, createPSSKeyVerifier } from "./algorithms/pss";
import { createECDSASigner, createECDSAVerifer } from "./algorithms/ecdsa";
import { createNoneSigner, createNoneVerifier } from "./algorithms/none";

const supportedAlgorithms = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'PS256', 'PS384', 'PS512',
    'ES256', 'ES384', 'ES512',
    'none'
];

type Algorithm =
    'HS256' | 'HS384' | 'HS512' |
    'RS256' | 'RS384' | 'RS512' |
    'PS256' | 'PS384' | 'PS512' |
    'ES256' | 'ES384' | 'ES512' |
    'none';

export function jwa(algorithm: Algorithm) {
    const signerFactories: { [alg: string]: SignerFactory } = {
        hs: createHmacSigner,
        rs: createRsaSigner,
        ps: createPSSKeySigner,
        es: createECDSASigner,
        none: createNoneSigner,
    };
    const verifierFactories: { [alg: string]: VerifierFactory } = {
        hs: createHmacVerifier,
        rs: createRsaVerifier,
        ps: createPSSKeyVerifier,
        es: createECDSAVerifer,
        none: createNoneVerifier,
    };
    const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i);
    if (!match)
        throw TypeError(
            `"${algorithm}" is not a valid algorithm.\n\t`
            + 'Supported algorithms are:\n\t'
            + `${supportedAlgorithms.join(', ')}.`
        );

    // Match (RS|PS|ES|HS) or (none)
    const algo: string = (match[1] || match[3]).toLowerCase();
    // Match (256|384|512)
    const bits = match[2] as Bit;

    return {
        sign: signerFactories[algo](bits),
        verify: verifierFactories[algo](bits),
    }
};
