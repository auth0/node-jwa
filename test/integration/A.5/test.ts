/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.5
 */

import fs from 'fs';
import path from 'path';
import { jwa } from '../../../src';

test('A.5: Example Unsecured JWS', () => {
	const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
	const algo = jwa('none');

	expect(algo.sign(input)).toBe('');
	expect(algo.verify(input, '')).toBe(true);
});
