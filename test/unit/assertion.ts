import {
    assertPrivateKeyHasValidType,
    assertPublicKeyHasValidType,
    assertSecretKeyHasValidType
} from '../../src/assertion';
import { KeyObject, createPublicKey } from 'crypto';

describe('Assertion', () => {
    describe('#assertPrivateKeyHasValidType', () => {
        it('throws if given a number', () => {
            const input = 999999999999999999999999999999999999999;

            expect(() => assertPrivateKeyHasValidType(input)).toThrowError(TypeError);
        });

        it('does not throw when given a string', () => {
            const input = 'super secret private key';
            expect(() => assertPrivateKeyHasValidType(input)).not.toThrow();
        });

        it('does not throw when given a KeyObject', () => {
            const input: KeyObject = createPublicKey('super secret public key');
            expect(() => assertPrivateKeyHasValidType(input)).not.toThrow();
        });
    });

    describe('#assertPublicKeyHasValidType', () => {
        it('throws if given a number', () => {
            const input = 999999999999999999999999999999999999999;

            expect(() => assertPublicKeyHasValidType(input)).toThrowError(TypeError);
        });
    });
    describe('#assertSecretKeyHasValidType', () => {
        it('throws if given a number', () => {
            const input = 999999999999999999999999999999999999999;

            expect(() => assertSecretKeyHasValidType(input)).toThrowError(TypeError);
        });
    });
});