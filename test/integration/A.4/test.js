/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.4
 */

const fs = require('fs');
const path = require('path');

const Buffer = require('safe-buffer').Buffer;
const jwkToPem = require('jwk-to-pem');
const test = require('tap').test;

const jwa = require('../../../dist');

const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));

const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'));
const pubKey = jwkToPem(jwk);

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');

const algo = jwa('es512');

test('A.4', function (t) {
	t.plan(3);

	t.equivalent(input, inputFromBytes);

	t.ok(algo.verify(input, signature, pubKey));
	t.ok(algo.verify(input.toString('ascii'), signature, pubKey));
})
