/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.1
 */

import fs from 'fs';
import path from 'path';
import { jwa } from '../../../src';

test('A.1: JWS Using HMAC SHA-256', () => {
	const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
	const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));
	const key = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8')).k, 'base64');
	const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');
	const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')));

	const algo = jwa('HS256');

	expect(input).toEqual(inputFromBytes);
	expect(Buffer.from(signature, 'base64')).toEqual(signatureFromBytes);

	expect(algo.sign(input, key)).toEqual(signature);
	expect(algo.sign(input.toString('ascii'), key)).toBe(signature);

	expect(algo.verify(input, signature, key)).toBe(true);
	expect(algo.verify(input.toString('ascii'), signature, key)).toBe(true);
});
