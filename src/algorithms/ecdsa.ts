import { SignerFactory, VerifierFactory } from ".";
import { createRsaSigner, createRsaVerifier } from "./rsa";
import { derToJose, joseToDer } from 'ecdsa-sig-formatter';
export const createECDSASigner: SignerFactory = bits => (data, privateKey) =>
    derToJose(
        createRsaSigner(bits)(data, privateKey),
        `ES${bits}`
    );

export const createECDSAVerifer: VerifierFactory = bits => (data, signature, publicKey) =>
    createRsaVerifier(bits)(
        data,
        joseToDer(signature, `ES${bits}`).toString('base64'),
        publicKey
    );

