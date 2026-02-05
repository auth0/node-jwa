/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.3
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
const pubKey = jwkToPem(jwk)

const signature = fs.readFileSync(path.join(__dirname, 'signature.txt'), 'ascii')

const algo = jwa('ES256')

test('A.3', async () => {
	assert.deepStrictEqual(input, inputFromBytes)

	assert.ok(await algo.verify(input, signature, pubKey))
	assert.ok(await algo.verify(input.toString('ascii'), signature, pubKey))
})
