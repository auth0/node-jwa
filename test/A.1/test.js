/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.1
 */

const fs = require('fs');
const path = require('path');

const Buffer = require('safe-buffer').Buffer;
const test = require('tap').test;

const jwa = require('../../');

const input = fs.readFileSync(path.join(__dirname, 'input.txt'));
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')));

const key = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8')).k, 'base64');

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii');
const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')));

const algo = jwa('HS256');

test('A.1', function (t) {
	t.plan(6);

	t.equivalent(input, inputFromBytes);
	t.equivalent(Buffer.from(signature, 'base64'), signatureFromBytes);

	t.equal(algo.sign(input, key), signature);
	t.equal(algo.sign(input.toString('ascii'), key), signature);

	t.ok(algo.verify(input, signature, key));
	t.ok(algo.verify(input.toString('ascii'), signature, key));
})
