import { SignerFactory, VerifierFactory } from ".";

export const createNoneSigner: SignerFactory = _ => () => '';

export const createNoneVerifier: VerifierFactory = _ => (_data, signature) => signature === '';
