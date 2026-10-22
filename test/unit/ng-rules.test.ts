import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { compilePcre, hasEmptyAlternative, parsePcre, removals } from '../../src/lib/ng/pcre.ts'
import { CHECK_ORDER, nginxUnquote, nginxUnquoteMapped, parseFirewall, RULESET_SOURCE } from '../../src/lib/ng/rules.ts'

const root = new URL('../../', import.meta.url)
const text = readFileSync(new URL('rules/8g-firewall.conf', root), 'utf8')
const fileLines = text.split('\n')
const groups = parseFirewall(text)
const rules = [...groups.values()].flatMap((g) => g.rules)

test('the shipped file is nG-SetEnvIf 8G v1.5, and its six maps parse completely, 118 rules', () => {
  assert.equal(fileLines[0], RULESET_SOURCE.header)
  const counts = Object.fromEntries([...groups].map(([id, g]) => [id, g.rules.length]))
  assert.deepEqual(counts, {
    bad_cookie: 1,
    not_allowed_method: 1,
    bad_referer: 4,
    bad_bot: 14,
    bad_querystring: 41,
    bad_request: 57,
  })
  assert.equal(rules.length, 118)
  assert.deepEqual([...groups.keys()], CHECK_ORDER)
  assert.deepEqual(
    [...groups.values()].map((g) => `${g.field}:${g.input}:${g.status}:${g.order}`),
    ['cookie:http_cookie:403:0', 'method:request_method:405:1', 'referer:http_referer:403:2', 'bot:http_user_agent:403:3', 'querystring:query_string:403:4', 'request:uri:403:5'],
  )
})

test('every rule keeps its number, file line and exact source line', () => {
  for (const g of groups.values()) {
    assert.deepEqual(g.rules.map((r) => r.number), g.rules.map((_, i) => i + 1), g.id)
    for (const r of g.rules) {
      assert.equal(fileLines[r.line - 1], r.sourceLine)
      assert.equal(r.sourceLine, `\t"~*${r.source}" ${r.number};`)
    }
  }
  const bot3 = groups.get('bad_bot')!.rules[2]
  assert.equal(bot3.line, 130)
  assert.equal(bot3.source, 'ahrefs|archiver|curl|libwww-perl|pycurl|scan')
  assert.equal(groups.get('bad_request')!.rules[41].line, 105)
})

test("nginx's own unquoting: \\\\ \\\" \\' become one character, every other backslash stays", () => {
  const bot2 = groups.get('bad_bot')!.rules[1]
  assert.equal(bot2.pattern, '&lt;|%0a|%0d|%27|%3c|%3e|%00|0x00|\\\\\\x22|\\\\"')
  assert.ok(bot2.regex.test('a\\"b'), 'a backslash then a quote')
  assert.ok(!bot2.regex.test('a"b'), 'a quote alone')
  const req3 = groups.get('bad_request')!.rules[2]
  assert.equal(req3.pattern, '\\^|`|<|>|\\\\|\\|')
  const qs31 = groups.get('bad_querystring')!.rules[30]
  assert.ok(qs31.pattern.startsWith('\\\\x00|(?:"|%22|\'|%27)?0'))
  assert.ok(qs31.regex.test('a\\x00'), 'the text \\x00, not a NUL byte')
  assert.equal(nginxUnquote('a\\tb\\nc\\rd\\qe'), 'a\tb\nc\rd\\qe')
  const m = nginxUnquoteMapped('a\\\\b\\"c')
  assert.equal(m.text, 'a\\b"c')
  assert.deepEqual(m.map, [0, 1, 3, 4, 6, 7])
})

test('all 118 patterns compile as JavaScript with flag i, as written and as translated', () => {
  for (const r of rules) {
    assert.doesNotThrow(() => new RegExp(r.pattern, 'i'), `${r.group} ${r.number}`)
    assert.equal(r.regex.flags, 'i')
    assert.match(r.pattern, /^[\x20-\x7e]+$/, `${r.group} ${r.number} is printable ASCII`)
  }
})

test('the PCRE constructs JavaScript reads differently are listed per rule and translated', () => {
  const by = (d: string) => rules.filter((r) => r.differences.includes(d as never)).map((r) => `${r.group}_${r.number}`)
  assert.deepEqual(by('space'), ['bad_referer_1', 'bad_referer_3', 'bad_bot_4', 'bad_querystring_4', 'bad_request_29'])
  assert.equal(by('dollar').length, 14)
  assert.equal(by('dot').length, 24)
  assert.equal(rules.filter((r) => r.differences.length).length, 41)
  // PCRE's meaning, kept: . matches CR, $ matches before a final LF, \s does not match 0xA0.
  assert.ok(compilePcre('eval.*\\)').test('eval\r)'))
  assert.ok(!new RegExp('eval.*\\)', 'i').test('eval\r)'), 'plain JavaScript differs')
  assert.ok(compilePcre('\\.env$').test('/.env\n'))
  assert.ok(!compilePcre('\\.env$').test('/.env\n\n'))
  assert.ok(!compilePcre('a\\sb').test('a\xA0b'))
  assert.ok(compilePcre('a\\sb').test('a\x0Bb'))
  assert.ok(compilePcre('[^\\s]x').test('\xA0x'))
})

test('the translation changes nothing but those three gaps', () => {
  const alphabet = 'aAbsSzZ019%2fF/\\.:;"\'`<>^|&=?+-_*()[]{}$# \t\x80\xC3\xE9\xFF'
  let seed = 7
  const rand = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648
  const samples = Array.from({ length: 400 }, () =>
    Array.from({ length: 1 + Math.floor(rand() * 24) }, () => alphabet[Math.floor(rand() * alphabet.length)]).join(''),
  )
  for (const r of rules) {
    const plain = new RegExp(r.pattern, 'i')
    const words = r.pattern.match(/[a-z_]{3,}/gi) ?? []
    for (const s of [...samples, ...words, ...words.map((w) => `/${w}.php`), ...words.map((w) => `x${w}(1)`)]) {
      assert.equal(r.regex.test(s), plain.test(s), `${r.group} ${r.number} on ${JSON.stringify(s)}`)
    }
  }
})

test('the PCRE reader refuses what it cannot translate, so a new release fails loudly', () => {
  for (const p of ['(?i)a', 'a++', 'a{2}+', '\\Z', '\\A', '[[:alpha:]]', '(?>x)', '[]a]', '\\x4', '(?<n>a)', '(a', 'a)', '\\Qa\\E']) {
    assert.throws(() => parsePcre(p), /unsupported PCRE/, p)
  }
  assert.doesNotThrow(() => parsePcre('a+?b*?c??(?<!SAML)d{1,22}e\\{0\\}'))
})

test('the file parser throws on any line it does not understand', () => {
  assert.throws(() => parseFirewall('map $http_user_agent $bad_bot_ng {\n  ~*(x) 1;\n}'), /not a rule/)
  assert.throws(() => parseFirewall('map $uri $other_ng {\n}'), /unknown map variable/)
  assert.throws(() => parseFirewall('map $uri $bad_bot_ng {\n}'), /reads \$uri, expected \$http_user_agent/)
  assert.throws(() => parseFirewall(text.replace('"~*,,," 1;', '"~*,,," 1')), /not a rule/)
  assert.throws(() => parseFirewall(text.replace(/map \$http_cookie[\s\S]*?\n\}\n/, '')), /missing maps: bad_cookie/)
})

test('taking any alternative out never leaves an empty group or a dangling |', () => {
  let n = 0
  for (const r of rules) {
    assert.ok(!hasEmptyAlternative(r.pattern), `${r.group} ${r.number} starts clean`)
    for (const x of removals(r.pattern)) {
      const next = r.pattern.slice(0, x.start) + r.pattern.slice(x.end)
      assert.ok(!hasEmptyAlternative(next), `${r.group} ${r.number} without ${x.text}: ${next}`)
      assert.doesNotThrow(() => compilePcre(next))
      n++
    }
  }
  assert.ok(n > 700, `${n} removals checked`)
})
