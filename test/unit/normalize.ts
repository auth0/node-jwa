
import { normalizeInput } from '../../src/normalize';

describe('Normalize', () => {
    describe('#normalizeInput', () => {
        it('returns a string when given a number', () => {
            const input = 42;
            const expectedOutput = '42';

            const actualOutput = normalizeInput(input);

            expect(typeof actualOutput).toBe('string');
            expect(actualOutput).toBe(expectedOutput);
        });

        it('returns a string when given a string', () => {
            const input = '42';
            const expectedOutput = '42';

            const actualOutput = normalizeInput(input);

            expect(typeof actualOutput).toBe('string');
            expect(actualOutput).toBe(expectedOutput);
        });

        it('returns a buffer when given a buffer', () => {
            const input = Buffer.from('thanos did nothing wrong', 'utf8');
            const expectedOutput = Buffer.from('thanos did nothing wrong', "utf8");

            const actualOutput = normalizeInput(input);

            expect(typeof actualOutput).toBe('object');
            expect(actualOutput).toBeInstanceOf(Buffer);
            expect(actualOutput.toString()).toBe(expectedOutput.toString());
        });

        it('returns a string of "null" when given null', () => {
            const input = null;
            const expectedOutput = 'null';

            const actualOutput = normalizeInput(input);

            expect(typeof actualOutput).toBe('string');
            expect(actualOutput).toBe(expectedOutput);
        });

        it('returns undefined when given undefined', () => {
            const input = undefined;

            const actualOutput = normalizeInput(input);

            expect(actualOutput).toBeUndefined();
        });
    });
});