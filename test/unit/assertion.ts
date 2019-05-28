import {
    assertPrivateKeyHasValidType,
    assertPublicKeyHasValidType,
    assertSecretKeyHasValidType
} from '../../src/assertion';
import { KeyObject, createPublicKey } from 'crypto';
import { readFile } from 'fs';
import { promisify } from 'util';
import { join } from 'path';
const rf = promisify(readFile);

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

        if(createPublicKey) { // Node 11+
            it('does not throw when given a KeyObject', async () => {
                const key = await rf(join(__dirname, '..', 'fixtures', 'rsa-public.pem'));
                const input: KeyObject = createPublicKey(key);
                expect(() => assertPrivateKeyHasValidType(input)).not.toThrow();
            });
        }
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