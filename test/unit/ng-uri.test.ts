import assert from 'node:assert/strict'
import { test } from 'node:test'
import { normalizeUri, splitRequestUri } from '../../src/lib/ng/uri.ts'

// Every expected value below is what nginx 1.27.5 itself gives: test/nginx/run.sh sends the same requests and compares.
const URI: [string, string][] = [
  ['/', '/'],
  ['//blogs/media/media/cache.php', '/blogs/media/media/cache.php'],
  ['//wp-admin///x.php', '/wp-admin/x.php'],
  ['/a///b', '/a/b'],
  ['/a%2f%2f%2fb', '/a/b'],
  ['/a/%2f/b', '/a/b'],
  ['/wp-content%2fplugins%2fx%2fshell.php', '/wp-content/plugins/x/shell.php'],
  ['/wp-content/plugins/%2e%2e/%2e%2e/wp-config.php', '/wp-config.php'],
  ['/x/%2E%2E/.ENV', '/.ENV'],
  ['/a/./b/../wp-config.php.bak', '/a/wp-config.php.bak'],
  ['/A/B/../C', '/A/C'],
  ['/a/..', '/'],
  ['/a/.', '/a/'],
  ['/a/.%2e/b', '/b'],
  ['/a/..%2fb', '/b'],
  ['/%25', '/%'],
  ['/%2541', '/%41'],
  ['/a%2500', '/a%00'],
  ['/%257eroot/', '/%7eroot/'],
  ['/%7eroot/', '/~root/'],
  ['/a%23b', '/a#b'],
  ['/a%3f%3f', '/a??'],
  ['/a+b%20c', '/a+b c'],
  ['/x+union+all+select+1', '/x+union+all+select+1'],
  ['/x/.htaccess%0a', '/x/.htaccess\n'],
  ['/eval%0d)', '/eval\r)'],
  ['/caf%C3%A9/menu/', '/caf\xC3\xA9/menu/'],
  ['/ok#/.env', '/ok'],
  ['/x\\y', '/x\\y'],
]

test('$uri is decoded once, slashes merged, dot segments resolved, exactly as nginx builds it', () => {
  for (const [path, uri] of URI) {
    assert.deepEqual(normalizeUri(path), { ok: true, uri }, path)
  }
})

test('nginx refuses these with a 400 before any map runs', () => {
  const bad: [string, string][] = [
    ['/a%zz', 'bad_escape'],
    ['/a%', 'bad_escape'],
    ['/a%2', 'bad_escape'],
    ['/a%00b', 'nul'],
    ['/../etc/passwd', 'above_root'],
    ['/a/../../x', 'above_root'],
    ['/%2e%2e/x', 'above_root'],
    ['/a/%2e%2e/%2e%2e/x', 'above_root'],
    ['/..', 'above_root'],
    ['x', 'not_a_path'],
  ]
  for (const [path, problem] of bad) {
    const r = normalizeUri(path)
    assert.ok(!r.ok && r.problem === problem, `${path}: ${JSON.stringify(r)}`)
    assert.ok(!r.ok && r.reason.length > 10)
  }
})

test('with merge_slashes off, // survives (nginx merges by default, and the harness runs the default)', () => {
  assert.deepEqual(normalizeUri('/a//b/%2f', false), { ok: true, uri: '/a//b//' })
})

test('$query_string is raw: after the first ?, never decoded, and it stops at a #', () => {
  assert.deepEqual(splitRequestUri('/a%3fb?c=1'), { path: '/a%3fb', queryString: 'c=1', hasQuery: true })
  assert.deepEqual(splitRequestUri('/?url=http%3a%2f%2fx+y'), { path: '/', queryString: 'url=http%3a%2f%2fx+y', hasQuery: true })
  assert.deepEqual(splitRequestUri('/a?b?c=..%2f'), { path: '/a', queryString: 'b?c=..%2f', hasQuery: true })
  assert.deepEqual(splitRequestUri('/?'), { path: '/', queryString: '', hasQuery: true })
  assert.deepEqual(splitRequestUri('/x'), { path: '/x', queryString: '', hasQuery: false })
  // A fragment: browsers and curl never send one, but nginx 1.27 cuts the query string there, and a # before the
  // first ? leaves no query string at all.
  assert.deepEqual(splitRequestUri('/ok?x=1#/etc/passwd'), { path: '/ok', queryString: 'x=1', hasQuery: true })
  assert.deepEqual(splitRequestUri('/ok#x?y=etc/passwd'), { path: '/ok', queryString: '', hasQuery: false })
})
