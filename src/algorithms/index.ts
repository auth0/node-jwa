import { KeyObject } from "crypto";

export type Bit = '256' | '384' | '512';

export type PublicKey = string | Object | Buffer | KeyObject;

export interface SignerFactory {
    (bits: Bit): (data: any, privateKey?: string | Buffer) => string;
}

export interface VerifierFactory {
    (bits: Bit): (data: any, signature: string, publicKey?: PublicKey) => boolean;
}
