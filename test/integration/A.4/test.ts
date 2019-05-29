/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.4
 */

import fs from 'fs';
import path from 'path';
import { jwa } from '../../../src';

const jwkToPem = require('jwk-to-pem');

test('A.4: JWS Using ECDSA P-521 SHA-512', () => {
	const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
	const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));

	const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'));
	const pubKey = jwkToPem(jwk);

	const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');

	const algo = jwa('ES512');

	expect(input).toEqual(inputFromBytes);

	expect(algo.verify(input, signature, pubKey)).toBe(true);
	expect(algo.verify(input.toString('ascii'), signature, pubKey)).toBe(true);
})
