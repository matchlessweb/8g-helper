import assert from 'node:assert/strict'
import { test } from 'node:test'
import { highlightNginx, highlightShell } from '../../src/lib/highlight.ts'

test('nginx tokens keep every character and classify the parts', () => {
  const src = '# a comment\nset $allow7g_x_bad_request_15 "";\nif ($request_uri ~ "^/a(\\?|$)") {\n    set $7g_drop_bad_request 0;\n}\n'
  const lines = highlightNginx(src)
  assert.equal(lines.map((l) => l.map((t) => t.text).join('')).join('\n') + '\n', src)
  assert.deepEqual(lines[0], [{ kind: 'comment', text: '# a comment' }])
  const kinds = lines[2].filter((t) => t.kind !== 'text').map((t) => t.kind)
  assert.deepEqual(kinds, ['keyword', 'variable', 'operator', 'string'])
  assert.ok(lines[3].some((t) => t.kind === 'number' && t.text === '0'))
})

test('shell tokens keep every character', () => {
  const src = "curl -s -o /dev/null -w '%{http_code}\\n' -A 'it'\\''s' 'https://a.com/x?y=1'"
  const [line] = highlightShell(src)
  assert.equal(line.map((t) => t.text).join(''), src)
  assert.equal(line[0].kind, 'command')
  assert.ok(line.filter((t) => t.kind === 'flag').length === 4)
  const reload = highlightShell('nginx -t && gp ngx reload')[0]
  assert.deepEqual(reload.filter((t) => t.kind === 'command').map((t) => t.text), ['nginx', 'gp'])
})
