import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { analyze, analyzeLine, type LineResult } from '../../src/lib/ng/analyze.ts'
import { matchGroup } from '../../src/lib/ng/match.ts'
import { CHECK_ORDER, parseFirewall } from '../../src/lib/ng/rules.ts'
import { VERDICT_TITLE } from '../../src/lib/ng/verdict.ts'

const root = new URL('../../', import.meta.url)
const groups = parseFirewall(readFileSync(new URL('rules/8g-firewall.conf', root), 'utf8'))
const load = (name: string) => readFileSync(new URL(`test/fixtures/${name}`, root), 'utf8')
type Ok = Extract<LineResult, { ok: true }>
const okAll = (text: string): Ok[] =>
  analyze(text, groups).map((r) => {
    assert.ok(r.ok, r.ok ? '' : r.reason)
    return r
  })
const real = okAll(load('8g-log-samples.txt'))
const rebuilt = okAll(load('8g-log-reconstructed.txt'))
const synthetic = okAll(load('8g-log-synthetic.txt'))
const one = (raw: string): Ok => okAll(raw)[0]
const g = (r: Ok, field: string) => r.groups.find((x) => x.group.field === field)!
const BASE = 'cookie=0 method=0 referer=0 bot=0 querystring=0 request=0'
const ng8 = (status: string, request: string, fields: string, ua = 'Mozilla/5.0', ref = '-') =>
  `2026-10-22T20:00:00+00:00 ${status} "${request}" ${fields} ip=192.0.2.1 ua="${ua}" ref="${ref}"`
const nums = (over: Record<string, number>) => BASE.replace(/(\w+)=0/g, (_, k: string) => `${k}=${over[k] ?? 0}`)

test('every number every 8G log line logged is what 8G v1.5 gives (cookies aside)', () => {
  let confirmed = 0
  for (const r of [...real, ...rebuilt, ...synthetic].filter((x) => x.line.format === 'ng8')) {
    for (const x of r.groups) {
      if (x.group.id === 'bad_cookie') {
        assert.equal(x.check?.status, 'unchecked')
        continue
      }
      assert.equal(x.check?.status, 'confirmed', `${r.line.raw}\n${x.group.field}: ${x.check?.note}`)
      if (x.logged) confirmed++
    }
  }
  assert.ok(confirmed >= 60, `${confirmed} non-zero numbers confirmed`)
})

test('real lines: two groups on one line, slashes merged, 444 is watch mode, a referrer with no scheme', () => {
  const mozlila = real.filter((r) => r.line.userAgent?.startsWith('Mozlila'))
  assert.equal(mozlila.length, 2)
  for (const r of mozlila) {
    assert.ok(r.line.requestUri!.startsWith('//'))
    assert.equal(r.line.uri, r.line.requestUri!.slice(1))
    assert.deepEqual([g(r, 'bot').logged, g(r, 'request').logged], [10, 42])
    assert.equal(g(r, 'bot').matches[0].matched.text, 'Mozlila')
    assert.equal(g(r, 'request').matches[0].matched.text, '/cache.php')
    assert.equal(r.fired?.group.field, 'bot', '8g.conf checks bot before request')
    assert.equal(r.line.referer, 'www.google.com')
    assert.equal(g(r, 'referer').check?.status, 'confirmed')
    assert.equal(r.verdict?.kind, 'attack')
  }
  const claudeXmlrpc = real.find((r) => r.line.uri === '/xmlrpc.php' && r.line.userAgent?.includes('ClaudeBot'))!
  assert.deepEqual([g(claudeXmlrpc, 'bot').logged, g(claudeXmlrpc, 'request').logged], [7, 49])
  for (const r of real.filter((x) => x.line.status === '444')) {
    assert.equal(r.mode, 'watch', 'GridPane refused xmlrpc itself; 8G only logged it')
    assert.equal(g(r, 'request').logged, 49)
  }
  assert.ok(real.every((r) => r.mode === 'watch'))
  const curl = real[0]
  assert.equal(curl.line.status, '412')
  assert.equal(curl.fired?.number, 3)
  assert.equal(curl.fired?.from, 'log')
  assert.deepEqual(g(curl, 'bot').matches.map((m) => [m.rule.number, m.rule.line, m.matched.text, m.first]), [[3, 130, 'curl', true]])
  assert.equal(g(curl, 'bot').matches[0].rule.sourceLine, '\t"~*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3;')
})

test('a shortened line: the logged rule is still confirmed, and the match on the "..." is set aside', () => {
  const r = real.find((x) => x.line.queryString?.startsWith('wp_insert_user'))!
  assert.equal(r.line.method, 'HEAD')
  assert.equal(r.line.cut, true)
  const qs = g(r, 'querystring')
  assert.deepEqual(qs.matches.map((m) => [m.rule.number, m.matched.text, m.inCut, m.first]), [
    [18, '...', true, false],
    [38, 'wp_insert_user', false, true],
  ])
  assert.equal(qs.check?.status, 'confirmed')
  assert.match(qs.check!.note, /querystring rule 18 matched only at the shortened part of the line/)
  // When the logged rule needs the shortened part, it cannot be re-checked: never a mismatch.
  const dep = one(ng8('200', 'GET /?x=Abcd...', nums({ querystring: 18 })))
  assert.equal(g(dep, 'querystring').check?.status, 'unchecked')
  assert.equal(g(dep, 'querystring').check?.reason, 'cut')
  const clear = one(ng8('200', 'GET /?wget=1&q=Abcd...', nums({ querystring: 38 })))
  assert.equal(g(clear, 'querystring').check?.status, 'confirmed', 'wget is clear of the shortened text')
  const edge = one(ng8('200', 'GET /?q=wget...', nums({ querystring: 38 })))
  assert.deepEqual(g(edge, 'querystring').matches.map((m) => [m.rule.number, m.inCut]), [[18, true], [38, true]])
  assert.equal(g(edge, 'querystring').check?.reason, 'cut', 'the four kept characters touch the dots: what followed them is unknown')
  const later = matchGroup(groups.get('bad_querystring')!, 'a=Abcd...&b=../x')
  assert.deepEqual(later.map((m) => [m.rule.number, m.matched.index, m.inCut, m.first]), [[18, 12, false, true]], 'a rule that also matches clear of the cut is a real match')
  const pathCut = one(ng8('200', 'GET /wp-content/plug...', nums({ querystring: 5 })))
  assert.equal(g(pathCut, 'querystring').check?.reason, 'cut', 'a shortened path hides whether a query string followed')
  const uaCut = one(ng8('200', 'GET /?a=1', nums({ querystring: 5 }), 'Mozilla/5.0 (compatible; Abcd...'))
  assert.equal(g(uaCut, 'querystring').check?.status, 'mismatch', 'a shortened user agent does not excuse the query string')
  const lost = one(ng8('200', 'GET /?q=Abcd...', nums({ querystring: 37 })))
  assert.equal(g(lost, 'querystring').check?.reason, 'cut', 'the word that fired may be in the cut part')
})

test('reconstructed facts: each reproduces the rule the report recorded', () => {
  const stripe = rebuilt.find((r) => r.line.userAgent?.includes('MerchantSecurityScanner'))!
  assert.deepEqual(g(stripe, 'bot').matches.map((m) => [m.rule.number, m.matched.text, m.first]), [
    [3, 'Scan', true],
    [11, 'Scan', false],
  ])
  const bark = real.find((r) => r.line.userAgent?.includes('Barkrowler'))!
  assert.deepEqual(g(bark, 'bot').matches.map((m) => m.rule.number), [6])
  const byFirst = rebuilt.map((r) => `${r.fired?.group.field}${r.fired?.number}`)
  assert.deepEqual([...new Set(byFirst)].sort(), ['bot3', 'bot7', 'bot9', 'querystring39', 'querystring9', 'request28', 'request30', 'request41', 'request42', 'request46', 'request47', 'request57'].sort())
})

test('mode: enforce when the status is what 8G returns, watch otherwise; $ng_reason means enforce', () => {
  const enforce = synthetic.filter((r) => r.mode === 'enforce').map((r) => `${r.line.status}:${r.fired?.group.field}`)
  assert.deepEqual(enforce, ['403:bot', '405:method', '403:referer', '403:request', '403:querystring', '403:cookie', '403:querystring', '403:request'])
  assert.equal(one(ng8('403', 'DEBUG /', nums({ method: 1 }))).mode, 'watch', '8G would have answered 405, so the 403 came from elsewhere')
  assert.equal(one(ng8('200', 'MOVE /', nums({ method: 1 }))).mode, 'watch')
  const combined = synthetic.filter((r) => r.line.format === 'combined')
  assert.ok(combined.every((r) => r.mode === 'unknown'))
})

test('access log lines are matched from scratch in every group', () => {
  const [ahrefs, quoted, xmlrpc] = synthetic.filter((r) => r.line.format === 'combined')
  assert.equal(ahrefs.fired?.from, 'match')
  assert.equal(ahrefs.fired?.number, 3)
  assert.ok(ahrefs.groups.every((x) => x.logged === undefined && x.check === undefined))
  assert.equal(quoted.fired, undefined)
  assert.match(quoted.nothing!, /the 403 came from somewhere else: 7G/)
  assert.equal(xmlrpc.fired?.group.field, 'request')
  assert.equal(xmlrpc.verdict?.kind, 'judgment')
})

test('nothing matched: a short reason, by status', () => {
  const at = (status: string) =>
    one(`198.51.100.1 - - [22/Oct/2026:20:00:00 +0000] "GET /about/ HTTP/1.1" ${status} 5 "-" "Mozilla/5.0"`).nothing
  assert.match(at('403')!, /somewhere else/)
  assert.match(at('405')!, /nginx itself/)
  assert.match(at('444')!, /closed the connection/)
  assert.match(at('200')!, /lets it through/)
  assert.match(one(ng8('200', 'GET /', BASE)).nothing!, /Every group logged 0/)
})

test('a logged number stock 8G would not give is a mismatch, with the reason', () => {
  const curl = (n: number) => g(one(ng8('200', 'GET /', nums({ bot: n }), 'curl/8.7.1')), 'bot').check!
  assert.equal(curl(3).status, 'confirmed')
  assert.deepEqual([curl(5).status, curl(5).reason], ['mismatch', 'not_matched'])
  assert.deepEqual([curl(99).status, curl(99).reason], ['mismatch', 'no_such_rule'])
  assert.deepEqual([curl(0).status, curl(0).reason], ['mismatch', 'unlogged_match'])
  const stripe = g(one(ng8('200', 'GET /', nums({ bot: 11 }), 'MerchantSecurityScanner')), 'bot').check!
  assert.deepEqual([stripe.status, stripe.reason], ['mismatch', 'not_first'])
  assert.match(stripe.note, /stock 8G v1\.5 would log 3/)
})

test('could not check: cookies, a missing user agent, an address nginx refuses', () => {
  const cookie = synthetic.find((r) => r.fired?.group.id === 'bad_cookie')!
  assert.equal(g(cookie, 'cookie').check?.reason, 'cookie')
  assert.equal(g(cookie, 'cookie').loggedRule?.number, 1)
  assert.equal(cookie.verdict?.kind, 'judgment')
  const cutShort = one('2026-10-22T20:00:00+00:00 200 "GET /x" cookie=0 method=0 referer=0 bot=7 querystring=0 request=0 ip=192.0.2.1 ua="Mozilla/5.0 (compatible; Cla')
  assert.equal(g(cutShort, 'bot').check?.reason, 'missing')
  const refused = one(ng8('400', 'GET /a%zz', nums({ request: 3 })))
  assert.equal(g(refused, 'request').check?.reason, 'invalid_uri')
  assert.match(g(refused, 'request').check!.note, /400/)
})

test('every match in a group is listed, the first marked, as nginx returns only the first', () => {
  const qs = matchGroup(groups.get('bad_querystring')!, 'file=..%2f..%2fetc%2fpasswd')
  assert.deepEqual(qs.map((m) => [m.rule.number, m.first]), [[17, true], [18, false]])
  const req = matchGroup(groups.get('bad_request')!, '/a/wp-config.php.bak')
  assert.deepEqual(req.map((m) => [m.rule.number, m.matched.text, m.matched.index]), [[33, 'config.php', 6], [55, '.bak', 16]])
  assert.equal(CHECK_ORDER.length, real[0].groups.length)
})

test('verdicts: crawler policy for named crawlers, attacks for probes, false positives for known shapes', () => {
  const kinds = (rs: Ok[]) => rs.map((r) => `${r.fired?.group.field}${r.fired?.number}:${r.verdict?.kind}${r.verdict?.crawler ? `:${r.verdict.crawler}` : ''}`)
  assert.deepEqual(kinds(real), [
    'bot3:crawler:curl', 'bot3:crawler:curl', 'bot7:crawler:Anthropic', 'bot12:crawler:Seznam', 'bot10:attack', 'bot10:attack',
    'bot6:crawler:Babbar', 'bot6:crawler:Babbar', 'querystring38:attack', 'request49:judgment', 'request49:judgment',
    'bot7:crawler:Anthropic', 'bot7:crawler:Anthropic', 'request49:judgment', 'bot7:judgment',
  ])
  assert.deepEqual(kinds(rebuilt), [
    'bot7:crawler:DataForSEO', 'bot7:crawler:DataForSEO', 'bot3:crawler:Stripe', 'bot3:crawler:Stripe', 'bot3:crawler:Ahrefs',
    'bot3:crawler:Ahrefs', 'bot9:crawler:Go-http-client', 'bot9:crawler:Go-http-client', 'querystring39:false_positive',
    'request41:attack', 'request41:attack', 'request42:attack', 'request46:attack', 'request47:attack', 'request57:attack',
    'request57:attack', 'request28:attack', 'request28:attack', 'request30:attack', 'querystring9:false_positive',
  ])
  const v = (raw: string) => one(raw).verdict!
  assert.equal(v(ng8('200', 'GET /?s=1+union+select+2', nums({ querystring: 29 }))).kind, 'attack', 'a search with SQL in it')
  assert.equal(v(ng8('200', 'GET /?s=evaluation+(2024)', nums({ querystring: 21 }))).kind, 'false_positive')
  assert.equal(v(ng8('200', 'GET /old/', nums({ request: 28 }))).kind, 'false_positive', 'the site served it: a real page')
  assert.match(v(ng8('200', 'GET /old/', nums({ request: 28 }))).reason, /Rename the page, or allow the rule/)
  assert.equal(v(ng8('200', 'GET /', nums({ referer: 4 }), 'Mozilla/5.0', 'https://example.org/libido')).kind, 'judgment')
  assert.equal(v(ng8('200', 'GET /', nums({ bot: 11 }), 'Mozilla/5.0 (compatible; PetalBot)')).crawler, 'Huawei')
  assert.equal(v(ng8('200', 'GET /', nums({ bot: 6 }), 'SomeNewBot/1.0 blowfish')).kind, 'crawler')
  assert.equal(v(ng8('200', 'GET /', nums({ bot: 3 }), 'WPScan v3.8')).kind, 'attack')
  for (const r of [...real, ...rebuilt, ...synthetic].filter((x) => x.verdict)) {
    assert.equal(r.verdict!.title, VERDICT_TITLE[r.verdict!.kind])
    assert.doesNotMatch(r.verdict!.reason, /\b(?:colour|favour|behaviour|recognise|organise|licence)\b/i, 'US spelling')
  }
})

test('analyzeLine returns the 7G-style error shape for an unreadable line', () => {
  const r = analyzeLine('nothing to see', groups)
  assert.ok(!r.ok && r.raw === 'nothing to see' && r.reason.length > 0)
})
