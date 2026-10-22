import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { cutSpans, parseLogLine, printable, splitLines, toBytes, unescapeLog, type LogLine } from '../../src/lib/ng/logline.ts'

const root = new URL('../../', import.meta.url)
const fixture = (name: string) => splitLines(readFileSync(new URL(`test/fixtures/${name}`, root), 'utf8'))
const parse = (raw: string): LogLine => {
  const r = parseLogLine(raw)
  assert.ok(r.ok, r.ok ? '' : r.reason)
  return r.line
}

test('every fixture line parses, in the format it is written in', () => {
  const formats = (name: string) => fixture(name).map((l) => parse(l).format)
  assert.deepEqual(new Set(formats('8g-log-samples.txt')), new Set(['ng8']))
  assert.equal(formats('8g-log-samples.txt').length, 15)
  assert.deepEqual(new Set(formats('8g-log-reconstructed.txt')), new Set(['ng8']))
  assert.equal(formats('8g-log-reconstructed.txt').length, 20)
  const synthetic = formats('8g-log-synthetic.txt')
  assert.equal(synthetic.filter((f) => f === 'ng8').length, 36)
  assert.equal(synthetic.filter((f) => f === 'ng_reason').length, 2)
  assert.equal(synthetic.filter((f) => f === 'combined').length, 3)
})

test('our 8G log line: every field, the six numbers, ua="-" as absent', () => {
  const l = parse(
    '2026-10-22T17:12:37+00:00 412 "GET /purge/sample-post/" cookie=0 method=0 referer=0 bot=3 querystring=0 request=0 ip=203.0.113.10 ua="curl/8.7.1" ref="-"',
  )
  assert.equal(l.format, 'ng8')
  assert.equal(l.time, '2026-10-22T17:12:37+00:00')
  assert.equal(l.status, '412')
  assert.equal(l.method, 'GET')
  assert.equal(l.requestUri, '/purge/sample-post/')
  assert.equal(l.uri, '/purge/sample-post/')
  assert.equal(l.queryString, '')
  assert.equal(l.protocol, '')
  assert.equal(l.ip, '203.0.113.10')
  assert.equal(l.userAgent, 'curl/8.7.1')
  assert.equal(l.referer, '', 'ref="-" means the header was absent')
  assert.deepEqual(l.logged, { bad_cookie: 0, not_allowed_method: 0, bad_referer: 0, bad_bot: 3, bad_querystring: 0, bad_request: 0 })
  assert.equal(l.cut, false)
})

test('older 8G lines: ip= empty or a Cloudflare value, empty numbers read as 0', () => {
  const l = parse('2026-10-20T09:00:00+00:00 200 "GET /" cookie= method= referer= bot=3 querystring= request= ip= ua="curl/8.0" ref="-"')
  assert.equal(l.ip, '')
  assert.deepEqual(l.logged, { bad_cookie: 0, not_allowed_method: 0, bad_referer: 0, bad_bot: 3, bad_querystring: 0, bad_request: 0 })
  assert.equal(parse('2026-10-20T09:00:00+00:00 200 "GET /" cookie=0 method=0 referer=0 bot=3 querystring=0 request=0 ip=2001:db8::1 ua="curl/8.0" ref="-"').ip, '2001:db8::1')
})

test("nginx's log escaping is undone into bytes: \\x22, \\x5C, \\xA0", () => {
  const l = parse('2026-10-22T20:00:00+00:00 404 "GET /a\\x22b/j\\xA0x" cookie=0 method=0 referer=0 bot=2 querystring=0 request=0 ip=192.0.2.1 ua="Mozilla/5.0 x\\x5C\\x22y" ref="www.google.com"')
  assert.equal(l.requestUri, '/a"b/j\xA0x')
  assert.equal(l.userAgent, 'Mozilla/5.0 x\\"y')
  assert.equal(l.referer, 'www.google.com', 'a referrer with no scheme stays as logged')
  assert.equal(unescapeLog('a\\x5Cx41'), 'a\\x41', 'an escaped backslash before x41 is not decoded twice')
  assert.equal(unescapeLog('Apache \\"q\\" \\\\ end'), 'Apache "q" \\ end')
  assert.equal(printable('/j\xA0x\n'), '/j\\xA0x\\x0A')
  assert.equal(toBytes('café'), 'caf\xC3\xA9')
  assert.equal(toBytes('plain'), 'plain')
})

test('a line cut short in the middle still reads what it has; a missing user agent is undefined, not empty', () => {
  const l = parse('2026-10-22T20:00:00+00:00 200 "GET /x" cookie=0 method=0 referer=0 bot=7 querystring=0 request=0 ip=192.0.2.1 ua="Mozilla/5.0 (compatible; Claude')
  assert.equal(l.userAgent, undefined)
  assert.equal(l.referer, undefined)
  assert.equal(l.logged.bad_bot, 7)
})

test('shortened text is noticed: abcd... (as the report masks keys) and …', () => {
  assert.equal(parse('2026-10-22T05:21:02+00:00 200 "HEAD /?wp_insert_user=45531&_=1792..." cookie=0 method=0 referer=0 bot=0 querystring=38 request=0 ip=203.0.113.10 ua="x" ref="-"').cut, true)
  assert.deepEqual(cutSpans('a=1792...&b=2'), [{ start: 6, end: 9 }])
  assert.deepEqual(cutSpans(toBytes('t=abcd…')), [{ start: 6, end: 9 }], 'the three bytes of …')
  assert.deepEqual(cutSpans('/a/.../b'), [], 'three dots without four letters or digits before them are not a cut')
  assert.deepEqual(cutSpans('x12345...'), [], 'a longer run is not how the report cuts')
})

test('a line carrying $ng_reason, in a format of its own', () => {
  const l = parse('192.0.2.71 [22/Oct/2026:20:15:00 +0000] "GET /?s=how+to+get+started HTTP/2.0" 403 ":bad_querystring_39:"')
  assert.equal(l.format, 'ng_reason')
  assert.deepEqual(l.logged, { bad_querystring: 39 })
  assert.equal(l.method, 'GET')
  assert.equal(l.queryString, 's=how+to+get+started')
  assert.equal(l.protocol, 'HTTP/2.0')
  assert.equal(l.time, '22/Oct/2026:20:15:00 +0000')
  assert.equal(l.userAgent, undefined, 'unknown in a format of its own')
  const bare = parse('reason=:not_allowed_method_1: GET /x?y=1 HTTP/1.1')
  assert.deepEqual(bare.logged, { not_allowed_method: 1 })
  assert.equal(bare.requestUri, '/x?y=1')
  const none = parse('reason=:bad_cookie_1:')
  assert.equal(none.method, undefined)
  assert.equal(none.uri, undefined)
})

test('$ng_reason tokens inside the request itself are not read as the reason', () => {
  const l = parse('198.51.100.1 - - [22/Oct/2026:20:00:00 +0000] "GET /x?a=:bad_bot_3: HTTP/1.1" 200 5 "-" "Mozilla/5.0"')
  assert.equal(l.format, 'combined')
  assert.deepEqual(l.logged, {})
  const r = parse('198.51.100.1 - - [22/Oct/2026:20:00:00 +0000] "GET /a.php HTTP/1.1" 403 153 "-" "Mozilla/5.0" ":bad_request_41:"')
  assert.equal(r.format, 'ng_reason')
  assert.deepEqual(r.logged, { bad_request: 41 })
  assert.equal(r.userAgent, 'Mozilla/5.0')
})

test('combined access log lines, nginx and Apache', () => {
  const l = parse('198.51.100.74 - - [22/Oct/2026:20:16:30 +0000] "GET /search?q=%22hello%22 HTTP/1.1" 403 199 "-" "Mozilla/5.0 \\"quoted\\" agent"')
  assert.equal(l.format, 'combined')
  assert.equal(l.ip, '198.51.100.74')
  assert.equal(l.status, '403')
  assert.equal(l.userAgent, 'Mozilla/5.0 "quoted" agent')
  assert.equal(l.referer, '')
  assert.equal(l.path, '/search')
  assert.deepEqual(l.logged, {})
  const short = parse('198.51.100.1 - - [22/Oct/2026:20:00:00 +0000] "GET / HTTP/1.1" 200 5')
  assert.equal(short.userAgent, undefined, 'the common format has no user agent')
})

test('lines that are not readable say why', () => {
  const why = (raw: string) => {
    const r = parseLogLine(raw)
    assert.ok(!r.ok)
    return r.reason
  }
  assert.match(why('[21/Oct/2026:11:40:47 +0000] [":bad_request_27:"] 203.0.113.10 example.com "GET /.env HTTP/2.0" 403 0.000 "-" "x"'), /7G log line/)
  assert.match(why('2026-10-22T17:12:37+00:00 412 "GET /x" cookie=0 method=0 referer=0 bot=3'), /part of it is missing/)
  assert.match(why('referer=0 bot=3 querystring=0 request=0 ip=203.0.113.10 ua="curl/8.7.1" ref="-"'), /start is missing/)
  assert.match(why('hello there'), /not a line the 8G Helper can read/)
  assert.match(why('203.0.113.77 - - [22/Oct/2026:20:14:00 +0000] "-" 400 0 "-" "-"'), /empty \(-\)/)
  assert.match(why('203.0.113.77 - - [22/Oct/2026:20:14:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'), /not an HTTP request/)
  assert.deepEqual(splitLines('\n# a comment\n  a  \r\n\nb'), ['a', 'b'])
})
