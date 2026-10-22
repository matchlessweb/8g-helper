import assert from 'node:assert/strict'
import { test } from 'node:test'
import { bindLast } from '../../src/lib/text.ts'

test('a short last pair is bound, and nothing else changes', () => {
  assert.equal(bindLast('8G is doing its job.'), '8G is doing its job.')
  assert.equal(bindLast('Check again after every update. '), 'Check again after every update.')
})

test('a long last pair, or a single word, is left to wrap', () => {
  const path = 'Fix /var/www/example.com/nginx/8g/8g-firewall.conf'
  assert.equal(bindLast(path), path)
  assert.equal(bindLast('Make every copy identical, then edit them.'), 'Make every copy identical, then edit them.')
  assert.equal(bindLast('the rules are unchanged-upstream nginx-configuration.'), 'the rules are unchanged-upstream nginx-configuration.')
  assert.equal(bindLast('Rare.'), 'Rare.')
})
