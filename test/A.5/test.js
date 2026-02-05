/**
 * https://tools.ietf.org/html/rfc7515#appendix-A.5
 */

import { test } from 'node:test'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { jwa } from '../../index.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const input = fs.readFileSync(path.join(__dirname, 'input.txt'))

const algo = jwa('none')

test('A.5', async () => {
	assert.strictEqual(await algo.sign(input), '')
	assert.ok(await algo.verify(input, ''))
})
