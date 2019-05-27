/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.2
 */

import fs from 'fs';
import path from 'path';
import { jwa } from '../../../src';
const jwkToPem = require('jwk-to-pem');


test('A.2: JWS Using RSASSA-PKCS1-v1_5 SHA-256', () => {
	const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
	const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));
	const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'));
	const privKey = jwkToPem(jwk, { private: true });
	const pubKey = jwkToPem(jwk);
	const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');
	const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')));
	const algo = jwa('RS256');

	expect(input).toEqual(inputFromBytes);
	expect(Buffer.from(signature, 'base64')).toEqual(signatureFromBytes);

	expect(algo.sign(input, privKey)).toBe(signature);
	expect(algo.sign(input.toString('ascii'), privKey)).toBe(signature);

	expect(algo.verify(input, signature, pubKey)).toBe(true);
	expect(algo.verify(input.toString('ascii'), signature, pubKey)).toBe(true);
});
