import { Base64 } from '../../src/base64';

describe('Base64', () => {
    describe('#toBase64Url', () => {
        it('converts a base64 string to a base64 url format', () => {
            const input = btoa('foo bar baz'); // "Zm9vIGJhciBiYXo="
            const expectedOutput = input.replace('=', ''); // "Zm9vIGJhciBiYXo"
    
            const actualOutput = Base64.toBase64Url(input);
    
            expect(actualOutput).toBe(expectedOutput);
        });
    });

    describe('#fromBase64Url', () => {
        it('converts a base64 url string to base64', () => {
            const input = Base64.toBase64Url(btoa('foo bar baz')); // "Zm9vIGJhciBiYXo"
            const expectedOutput = input + '='; // "Zm9vIGJhciBiYXo="
    
            const actualOutput = Base64.fromBase64Url(input);
    
            expect(actualOutput).toBe(expectedOutput);
        });
    });
});
