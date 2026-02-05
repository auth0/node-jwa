/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.2
 */

import { test } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'node:buffer'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import jwkToPem from 'jwk-to-pem'
import { jwa } from '../../index.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const input = fs.readFileSync(path.join(__dirname, 'input.txt'))
const inputFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'input.bytes.json'), 'utf8')))

const jwk = JSON.parse(fs.readFileSync(path.join(__dirname, 'key.json'), 'utf8'))
const privKey = jwkToPem(jwk, { private: true })
const pubKey = jwkToPem(jwk)

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii')
const signatureFromBytes = Buffer.from(JSON.parse(fs.readFileSync(path.join(__dirname, 'signature.bytes.json'), 'utf8')))

const algo = jwa('RS256')

test('A.2', async () => {
	assert.deepStrictEqual(input, inputFromBytes)
	assert.deepStrictEqual(Buffer.from(signature, 'base64'), signatureFromBytes)

	assert.strictEqual(await algo.sign(input, privKey), signature)
	assert.strictEqual(await algo.sign(input.toString('ascii'), privKey), signature)

	assert.ok(await algo.verify(input, signature, pubKey))
	assert.ok(await algo.verify(input.toString('ascii'), signature, pubKey))
})
