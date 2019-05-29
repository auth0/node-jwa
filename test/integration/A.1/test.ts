/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.1
 */

import fs from 'fs';
import path from 'path';
import { jwa } from '../../../src';
import { k } from './key.json';
import inputBytes from './input.bytes.json';
import signatureByte from './signature.bytes.json';

test('A.1: JWS Using HMAC SHA-256', () => {
	const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
	const inputFromBytes = Buffer.from(inputBytes);
	const secret = Buffer.from(k, 'base64');
	const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');
	const signatureFromBytes = Buffer.from(signatureByte);

	const algo = jwa('HS256');

	expect(input).toEqual(inputFromBytes);
	expect(Buffer.from(signature, 'base64')).toEqual(signatureFromBytes);

	expect(algo.sign(input, secret)).toEqual(signature);
	expect(algo.sign(input.toString('ascii'), secret)).toBe(signature);

	expect(algo.verify(input.toString('ascii'), signature, secret)).toBe(true);
	expect(algo.verify(input.toString('ascii'), signature, secret)).toBe(true);
});
