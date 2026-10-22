import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  buildAllowCommands,
  editsFor,
  findCopiesCommand,
  parseCopies,
  planAllow,
  ruleText,
  sedExpression,
  shellQuote,
  type AllowEdit,
  type AllowPlan,
} from '../../src/lib/ng/allowfix.ts'
import { analyze, type LineResult } from '../../src/lib/ng/analyze.ts'
import { matchGroup } from '../../src/lib/ng/match.ts'
import { isNameLike, removals } from '../../src/lib/ng/pcre.ts'
import { nginxUnquote, nginxUnquoteMapped, parseFirewall, type GroupId, type Rule } from '../../src/lib/ng/rules.ts'

const root = new URL('../../', import.meta.url)
const text = readFileSync(new URL('rules/8g-firewall.conf', root), 'utf8')
const groups = parseFirewall(text)
type Ok = Extract<LineResult, { ok: true }>
const results: Ok[] = ['8g-log-samples.txt', '8g-log-reconstructed.txt', '8g-log-synthetic.txt'].flatMap((f) =>
  analyze(readFileSync(new URL(`test/fixtures/${f}`, root), 'utf8'), groups).map((r) => {
    assert.ok(r.ok)
    return r
  }),
)
const lineOf = (pred: (r: Ok) => boolean): Ok => {
  const r = results.find(pred)
  assert.ok(r, 'fixture line not found')
  return r
}
const ua = (s: string) => lineOf((r) => r.line.userAgent?.includes(s) ?? false)
const uri = (s: string) => lineOf((r) => r.line.requestUri === s)
/** The plan for the group that fired on this line. */
const planOf = (r: Ok): AllowPlan => {
  const g = r.groups.find((x) => x.group.id === r.fired?.group.id)!
  const p = planAllow(g, r.groups)
  assert.ok(p)
  return p
}
const brief = (p: AllowPlan) => p.edits.map((e) => `${e.rule.group}_${e.rule.number}:${e.kind}:${e.tokens.join('+')}`)
const codes = (p: AllowPlan) => p.warnings.map((w) => w.code)

/** The file with each edit applied, keeping each line's indentation, as the sed does. shift: extra lines at the top. */
function applyEdits(src: string, edits: AllowEdit[], shift = 0): string {
  const ls = src.split('\n')
  for (const e of edits) {
    const i = e.rule.line - 1 + shift
    const indent = ls[i].match(/^\s*/)![0]
    assert.equal(ls[i].slice(indent.length), e.before)
    ls[i] = indent + e.after
  }
  return ls.join('\n')
}

const ahrefs = ua('AhrefsBot/7.0; +http')
const stripe = ua('MerchantSecurityScanner')
const aPhp = uri('/a.php')

test('Ahrefs: take ahrefs out of bot rule 3, as Jeff Starr advises', () => {
  const p = planOf(ahrefs)
  assert.deepEqual(brief(p), ['bad_bot_3:remove:ahrefs'])
  assert.equal(p.edits[0].before, '"~*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3;')
  assert.equal(p.edits[0].after, '"~*archiver|curl|libwww-perl|pycurl|scan" 3;')
  assert.deepEqual(codes(p), ['token_everywhere', 'server_wide', 'update'])
  assert.match(p.warnings[0].text, /every user agent containing “ahrefs” through/)
})

test('two rules match: both are edited, because the map moves on to the next one', () => {
  const p = planOf(stripe)
  assert.deepEqual(brief(p), ['bad_bot_3:remove:scan', 'bad_bot_11:remove:scan'])
  assert.equal(p.edits[0].after, '"~*ahrefs|archiver|curl|libwww-perl|pycurl" 3;')
  assert.ok(p.edits[1].after.includes('|rogerbot|scooter|'))
  assert.ok(codes(p).includes('other_rules'))
  // One rule, two names in the same request: Barkrowler's agent names babbar.tech too.
  assert.deepEqual(brief(planOf(ua('Barkrowler'))), ['bad_bot_6:remove:barkrowler+babbar'])
})

test('plans for the known false positives and the real lines', () => {
  assert.deepEqual(brief(planOf(lineOf((r) => r.line.queryString === 's=how+to+get+started'))), ['bad_querystring_39:remove:get'])
  assert.deepEqual(brief(planOf(lineOf((r) => r.line.queryString?.includes('redirect_uri') ?? false))), ['bad_querystring_9:remove:localhost'])
  assert.deepEqual(brief(planOf(ua('Jetpack by WordPress.com (Jetpack'))), ['bad_request_49:remove:xmlrpc'])
  assert.deepEqual(brief(planOf(uri('/old/'))), ['bad_request_28:remove:old'])
  assert.deepEqual(brief(planOf(uri('/site/'))), ['bad_request_30:remove:sites?'], 'the file spelling, ? and all')
  assert.deepEqual(brief(planOf(ua('ClaudeBot'))), ['bad_bot_7:remove:claudebot'])
  const mozlila = planOf(ua('Mozlila'))
  assert.deepEqual(brief(mozlila), ['bad_bot_10:remove:mozlila'])
  assert.ok(mozlila.warnings.some((w) => w.code === 'other_groups' && /request rule 42/.test(w.text)))
})

test('a rule that is not a list of names is commented out whole', () => {
  const p = planOf(aPhp)
  assert.deepEqual(brief(p), ['bad_request_41:comment:'])
  assert.equal(p.edits[0].after, `#${p.edits[0].before}`)
  assert.deepEqual(codes(p), ['rule_off', 'server_wide', 'update'])
})

test('a shortened line: the match at the dots is not edited, and the plan says so', () => {
  const p = planOf(lineOf((r) => r.line.queryString?.startsWith('wp_insert_user') ?? false))
  assert.deepEqual(brief(p), ['bad_querystring_38:remove:wp_insert_user'], 'rule 18 matched only the shortened "..."')
  assert.ok(codes(p).includes('shortened'))
})

test('cookies, and a logged rule that does not match here: comment out the logged rule', () => {
  const cookie = lineOf((r) => r.fired?.group.id === 'bad_cookie')
  const p = planOf(cookie)
  assert.equal(p.value, undefined)
  assert.deepEqual(brief(p), ['bad_cookie_1:comment:'])
  assert.match(p.warnings[0].text, /does not carry the cookies/)
  const [odd] = analyze(
    '2026-10-22T20:00:00+00:00 200 "GET /" cookie=0 method=0 referer=0 bot=5 querystring=0 request=0 ip=192.0.2.1 ua="curl/8.7.1" ref="-"',
    groups,
  )
  assert.ok(odd.ok)
  const bot = odd.groups.find((x) => x.group.id === 'bad_bot')!
  const q = planAllow(bot, odd.groups)!
  assert.deepEqual(brief(q), ['bad_bot_5:comment:'])
  assert.equal(q.warnings[0].code, 'whole_rule')
  assert.equal(planAllow(odd.groups.find((x) => x.group.id === 'bad_request')!), undefined, 'logged 0: nothing to allow')
  const combined = lineOf((r) => r.line.format === 'combined' && !r.fired)
  assert.ok(combined.groups.every((x) => planAllow(x) === undefined))
})

test('after every plan on every fixture line, no rule in that group matches the request', () => {
  let plans = 0
  let tokens = 0
  for (const r of results) {
    for (const g of r.groups) {
      const p = planAllow(g, r.groups)
      if (!p) continue
      plans++
      const edited = parseFirewall(applyEdits(text, p.edits))
      for (const e of p.edits) {
        assert.notEqual(e.after, e.before)
        if (e.kind === 'remove') {
          tokens += e.tokens.length
          assert.ok(e.tokens.length > 0 && e.tokens.every(isNameLike))
          const kept = edited.get(g.group.id)!.rules.find((x) => x.line === e.rule.line)!
          assert.ok(kept, 'the edited rule still parses')
        }
      }
      if (p.value === undefined || codes(p).includes('whole_rule')) continue
      const left = matchGroup(edited.get(g.group.id)!, p.value).filter((m) => !m.inCut)
      assert.deepEqual(left.map((m) => m.rule.number), [], `${r.line.raw}\n${brief(p).join(' ')}`)
    }
  }
  assert.ok(plans >= 60 && tokens >= 45, `${plans} plans, ${tokens} names taken out`)
  assert.deepEqual(editsFor(groups.get('bad_bot')!, 'Mozilla/5.0 (Macintosh)'), [], 'nothing matches: nothing to edit')
})

// Commands ---------------------------------------------------------------------------------------------------------

const S1 = '/var/www/site1.example.com/nginx/8g/8g-firewall.conf'
const S2 = '/var/www/site2.example.com/nginx/8g/8g-firewall.conf'

test('the read-only find command: every copy nginx loads or a site holds, each rule by its exact text', () => {
  const cmd = findCopiesCommand(planOf(stripe).edits)
  assert.ok(cmd.startsWith('{ nginx -T 2>/dev/null | sed -nE '))
  assert.ok(cmd.includes('ls -1 /var/www/*/nginx/8g/8g-firewall.conf 2>/dev/null; } | sort -u | while read -r f; do grep -HnF '))
  assert.ok(cmd.includes(`-e '"~*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3;'`))
  assert.ok(cmd.endsWith(` -- "$f" || echo "$f:0:none of these rules"; done`))
  assert.equal(shellQuote("it's"), `'it'\\''s'`)
})

test('reading the pasted listing: line numbers per copy, and every reason it cannot go ahead', () => {
  const edits = planOf(stripe).edits
  const [b3, b11] = edits.map((e) => e.before)
  const ok = parseCopies(`nginx: [warn] noise\n${S1}:130:\t${b3}\n${S1}:138:\t${b11}\n${S2}:131:\t${b3}\n${S2}:139:\t${b11}\n`, edits)
  assert.deepEqual(ok.copies, [
    { file: S1, lines: [130, 138] },
    { file: S2, lines: [131, 139] },
  ])
  assert.deepEqual(ok.problems, [])
  assert.equal(ok.notes.length, 2, 'site2 has its rules one line lower than 8G v1.5')
  const why = (out: string) => parseCopies(out, edits).problems
  assert.match(why('')[0], /No copy of 8g-firewall.conf was found/)
  assert.match(why(`${S1}:0:none of these rules`)[0], /does not have bot rule 3 or bot rule 11 as 8G v1.5 ships it/)
  assert.match(why(`${S1}:130:\t#${b3}\n${S1}:138:\t${b11}`)[0], /bot rule 3 is already commented out \(line 130\)/)
  assert.match(why(`${S1}:130:\t${b3}\n${S1}:200:\t${b3}\n${S1}:138:\t${b11}`)[0], /has bot rule 3 twice \(lines 130 and 200\)/)
  assert.match(why(`${S1}:130:\t${b3} # mine\n${S1}:138:\t${b11}`)[0], /other text on the line/)
  assert.match(why(`${S1}:138:\t${b11}`)[0], /does not have bot rule 3 as 8G v1\.5 ships it/)
})

test('the edit command: a subshell, a backup per copy, one exact sed per line, checked, then nginx -t', () => {
  const edits = [...planOf(stripe).edits, ...planOf(aPhp).edits]
  const c = buildAllowCommands(edits, [{ file: S1, lines: [130, 138, 104] }], '2026-10-22')
  assert.equal(c.backupSuffix, '.bak-8g-helper-2026-10-22')
  assert.ok(c.edit.startsWith('(\n') && c.edit.endsWith('\n)'))
  assert.ok(c.edit.includes(String.raw`-e '130s#^\([[:space:]]*\)"~\*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3;$#\1"~*ahrefs|archiver|curl|libwww-perl|pycurl" 3;#'`))
  assert.ok(c.edit.includes(String.raw`-e '104{\#^[[:space:]]*"~\*`))
  assert.ok(c.edit.includes(`[ "$(sed -n '130{s/^[[:space:]]*//;p}' '${S1}')" = '"~*ahrefs|archiver|curl|libwww-perl|pycurl" 3;' ]`))
  assert.ok(c.edit.includes('if [ "$ok" = 1 ] && nginx -t; then'))
  assert.ok(c.edit.includes('gp ngx reload'))
  assert.ok(c.edit.includes('for f; do mv "$f$b" "$f"; done'))
  assert.ok(!/\*\.conf|\/\*\//.test(c.edit), 'never edits through a glob')
  assert.throws(() => buildAllowCommands([], [{ file: S1, lines: [] }], 'd'), /nothing to edit/)
  assert.throws(() => buildAllowCommands(edits, [], 'd'), /no copies/)
  assert.throws(() => buildAllowCommands(edits, [{ file: S1, lines: [130] }], 'd'), /a line number for every edit/)
  assert.equal(sedExpression(planOf(ahrefs).edits[0], 7).slice(0, 2), '7s')
})

// Docker proofs: GNU sed on a fake two-site server, and nginx loading the edited file. ------------------------------

const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && 'docker is not running'
const run = (args: string[], input?: string) =>
  execFileSync('docker', ['run', '--rm', '-i', ...args], { encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'] })

test('on a fake GridPane server (ubuntu:24.04, GNU sed): find, edit both sites, refuse a rerun, restore, fail safe', { skip }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-allow-'))
  const www = join(dir, 'www')
  const site2Top = '# this copy has one line more at the top\n'
  for (const [site, body] of [['site1.example.com', text], ['site2.example.com', site2Top + text]]) {
    mkdirSync(join(www, site, 'nginx/8g'), { recursive: true })
    writeFileSync(join(www, site, 'nginx/8g/8g-firewall.conf'), body)
  }
  mkdirSync(join(dir, 'bin'))
  mkdirSync(join(dir, 'state'))
  // nginx -T names only site1's copy; the ls in the find command has to find site2's.
  writeFileSync(
    join(dir, 'bin/nginx'),
    `#!/bin/sh
case "$1" in
  -T) printf '# configuration file /etc/nginx/nginx.conf:\\nhttp {\\n    include ${S1};\\n}\\n' ;;
  -t) if [ -e /state/fail ]; then echo "nginx: [emerg] stub failure" >&2; exit 1; fi; echo "nginx: the configuration file syntax is ok" >&2 ;;
  *) exit 2 ;;
esac
`,
  )
  writeFileSync(join(dir, 'bin/gp'), '#!/bin/sh\necho "$*" >> /state/reloads\n')
  chmodSync(join(dir, 'bin/nginx'), 0o755)
  chmodSync(join(dir, 'bin/gp'), 0o755)
  // stdout whatever the exit status: a STOP ends the subshell with 1, as it should.
  const sh = (cmd: string) =>
    spawnSync(
      'docker',
      ['run', '--rm', '-i', '-v', `${www}:/var/www`, '-v', `${join(dir, 'bin')}:/stub:ro`, '-v', `${join(dir, 'state')}:/state`, '-e', 'PATH=/stub:/usr/bin:/bin', 'ubuntu:24.04', 'bash', '-s'],
      { encoding: 'utf8', input: cmd },
    ).stdout
  const file = (site: string) => readFileSync(join(www, site, 'nginx/8g/8g-firewall.conf'), 'utf8')
  const reloads = () => (existsSync(join(dir, 'state/reloads')) ? readFileSync(join(dir, 'state/reloads'), 'utf8') : '')
  const originals = [text, site2Top + text]
  const sites = ['site1.example.com', 'site2.example.com']
  const backups = () => sites.filter((s) => existsSync(join(www, s, 'nginx/8g/8g-firewall.conf.bak-8g-helper-2026-10-22')))

  assert.match(sh('sed --version | head -1'), /GNU sed/)
  const edits = [...planOf(stripe).edits, ...planOf(aPhp).edits]
  const listing = parseCopies(sh(findCopiesCommand(edits)), edits)
  assert.deepEqual(listing.problems, [])
  assert.deepEqual(listing.copies, [
    { file: S1, lines: [130, 138, 104] },
    { file: S2, lines: [131, 139, 105] },
  ])
  const cmds = buildAllowCommands(edits, listing.copies, '2026-10-22')

  // Edit both copies.
  const out = sh(cmds.edit)
  assert.match(out, /DONE: bot rule 3, bot rule 11, request rule 41 edited\. Copies: 2\./)
  const want = [applyEdits(text, edits), site2Top + applyEdits(text, edits)]
  assert.deepEqual(sites.map(file), want)
  assert.deepEqual(sites.map((s) => readFileSync(join(www, s, 'nginx/8g/8g-firewall.conf.bak-8g-helper-2026-10-22'), 'utf8')), originals)
  assert.equal(reloads(), 'ngx reload\n')
  assert.equal(file('site1.example.com').split('\n')[103], `\t#${planOf(aPhp).edits[0].before}`, 'the comment keeps the tab, then #')
  assert.equal(sh(cmds.verify).trim().split('\n').length, 6, 'three edited lines in each of two copies')
  for (const g of parseFirewall(want[0]).values()) assert.ok(g.rules.length > 0)

  // Run again: the backups exist, so nothing changes.
  assert.match(sh(cmds.edit), /STOP: .*already exists\. Nothing was changed\./)
  assert.deepEqual(sites.map(file), want)
  assert.equal(reloads(), 'ngx reload\n')

  // Undo.
  assert.match(sh(cmds.restore), /DONE: every copy is back/)
  assert.deepEqual(sites.map(file), originals)
  assert.deepEqual(backups(), [])
  assert.equal(reloads(), 'ngx reload\nngx reload\n')

  // nginx -t fails: every copy is put back, no backups are left, no reload.
  writeFileSync(join(dir, 'state/fail'), '')
  assert.match(sh(cmds.edit), /FAILED: every copy was put back from its backup, and nginx was not reloaded\./)
  assert.deepEqual(sites.map(file), originals)
  assert.deepEqual(backups(), [])
  assert.equal(reloads().split('\n').length - 1, 2)

  // A copy changed between the find and the edit: its sed changes nothing, the check sees it, all is put back.
  execFileSync('rm', [join(dir, 'state/fail')])
  writeFileSync(join(www, 'site2.example.com/nginx/8g/8g-firewall.conf'), site2Top + text.replace('pycurl|scan" 3;', 'pycurl|scan|mine" 3;'))
  const changed = sh(cmds.edit)
  assert.match(changed, new RegExp(`FAILED: ${S2} did not change as expected`))
  assert.match(changed, /every copy was put back/)
  assert.equal(file('site1.example.com'), text)
  assert.deepEqual(backups(), [])
  assert.equal(reloads().split('\n').length - 1, 2)
})

/** Every edit the helper could ever make: each rule commented out, and each name-like alternative taken out alone. */
function everyEdit(): AllowEdit[] {
  const out: AllowEdit[] = []
  for (const g of groups.values()) {
    for (const rule of g.rules) {
      const before = ruleText(rule)
      out.push({ rule, kind: 'comment', tokens: [], before, after: `#${before}` })
      const { map } = nginxUnquoteMapped(rule.source)
      for (const r of removals(rule.pattern).filter((x) => isNameLike(x.text))) {
        const source = rule.source.slice(0, map[r.start]) + rule.source.slice(map[r.end])
        assert.equal(nginxUnquote(source), rule.pattern.slice(0, r.start) + rule.pattern.slice(r.end))
        const quoted = `"~*${rule.source}"`
        out.push({ rule, kind: 'remove', tokens: [rule.source.slice(map[r.altStart], map[r.altEnd])], before, after: `"~*${source}"${before.slice(quoted.length)}` })
      }
    }
  }
  return out
}

test('every possible edit, through GNU sed (ubuntu:24.04): only that line changes, exactly as planned', { skip }, () => {
  const all = everyEdit()
  const dir = mkdtempSync(join(tmpdir(), 'ng-sed-'))
  writeFileSync(join(dir, 'orig'), text)
  const lines = ['set -u', 'n=0; bad=0']
  all.forEach((e, i) => {
    const L = e.rule.line
    lines.push(
      `cp /x/orig /x/w; sed -i -e ${shellQuote(sedExpression(e, L))} /x/w && [ "$(sed -n '${L}{s/^[[:space:]]*//;p}' /x/w)" = ${shellQuote(e.after)} ] && cmp -s <(sed '${L}d' /x/w) <(sed '${L}d' /x/orig) && n=$((n+1)) || { bad=$((bad+1)); echo "BAD ${i}"; }`,
    )
  })
  // The guard: on a line that does not read as expected, the sed changes nothing.
  const wrong = all.filter((e) => e.kind === 'remove').slice(0, 20)
  wrong.forEach((e, i) => lines.push(`cp /x/orig /x/w; sed -i -e ${shellQuote(sedExpression(e, e.rule.line + 1))} /x/w; cmp -s /x/w /x/orig && n=$((n+1)) || { bad=$((bad+1)); echo "GUARD ${i}"; }`))
  lines.push('echo "OK $n BAD $bad"')
  writeFileSync(join(dir, 'all.sh'), `${lines.join('\n')}\n`)
  const out = run(['-v', `${dir}:/x`, 'ubuntu:24.04', 'bash', '/x/all.sh'])
  assert.equal(out.trim(), `OK ${all.length + wrong.length} BAD 0`)
  assert.ok(all.length > 800, `${all.length} edits`)
})

const nginxImage = 'nginx:1.27'

test('nginx 1.27 loads every edited pattern (nginx -t), and fails on a broken one', { skip }, () => {
  const all = everyEdit()
  const dir = mkdtempSync(join(tmpdir(), 'ng-t-'))
  const input: Record<string, string> = {
    not_allowed_method: '$request_method',
    bad_cookie: '$http_cookie',
    bad_referer: '$http_referer',
    bad_bot: '$http_user_agent',
    bad_querystring: '$query_string',
    bad_request: '$uri',
  }
  const conf = (maps: string[]) =>
    `pid /tmp/t.pid;\nerror_log /dev/stderr warn;\nevents {}\nhttp {\n${maps.join('\n')}\nserver { listen 8080; return 200; }\n}\n`
  const maps = all.map((e, i) => `map ${input[e.rule.group]} $t${i} {\n\tdefault 0;\n\t${e.after}\n}`)
  writeFileSync(join(dir, 'good.conf'), conf(maps))
  writeFileSync(join(dir, 'bad.conf'), conf([...maps.slice(0, 3), 'map $uri $broken {\n\tdefault 0;\n\t"~*(?:a|" 1;\n}']))
  const t = (name: string) => spawnSync('docker', ['run', '--rm', '-v', `${dir}:/x:ro`, nginxImage, 'nginx', '-t', '-c', `/x/${name}`], { encoding: 'utf8' })
  const good = t('good.conf')
  assert.equal(good.status, 0, good.stderr)
  assert.match(good.stderr, /syntax is ok/)
  const bad = t('bad.conf')
  assert.notEqual(bad.status, 0)
  assert.match(bad.stderr, /pcre2?_compile\(\) failed|missing closing parenthesis/)
})

test('nginx 1.27 with the edited file: each request now gets 0 in that group, and other groups are unchanged', { skip }, () => {
  const harness = readFileSync(new URL('test/nginx/nginx.conf', root), 'utf8')
  const cases: { name: string; r: Ok; plan: AllowPlan }[] = [
    ['Ahrefs', ahrefs],
    ['Stripe', stripe],
    ['Barkrowler', ua('Barkrowler')],
    ['ClaudeBot', ua('ClaudeBot')],
    ['Mozlila', ua('Mozlila')],
    ['site search', lineOf((r) => r.line.queryString === 's=how+to+get+started')],
    ['OAuth localhost', lineOf((r) => r.line.queryString?.includes('redirect_uri') ?? false)],
    ['Jetpack xmlrpc', ua('Jetpack by WordPress.com (Jetpack')],
    ['/old/', uri('/old/')],
    ['/a.php', aPhp],
    ['wp_insert_user (cut)', lineOf((r) => r.line.queryString?.startsWith('wp_insert_user') ?? false)],
    ['DEBUG method', lineOf((r) => r.line.method === 'DEBUG')],
    ['referrer spam', lineOf((r) => r.fired?.group.id === 'bad_referer' && r.fired.number === 4)],
  ].map(([name, r]) => ({ name: name as string, r: r as Ok, plan: planOf(r as Ok) }))
  const dir = mkdtempSync(join(tmpdir(), 'ng-edited-'))
  const HEADERS: GroupId[] = ['bad_cookie', 'not_allowed_method', 'bad_referer', 'bad_bot', 'bad_querystring', 'bad_request']
  const bytes = (s: string): string =>
    `$'${[...s].map((ch) => (/[A-Za-z0-9/._,:;=+-]/.test(ch) ? ch : `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`)).join('')}'`
  const script = ['set -u']
  const variants = [{ name: 'stock', text }, ...cases.map((c) => ({ name: c.name, text: applyEdits(text, c.plan.edits) }))]
  variants.forEach((v, i) => {
    writeFileSync(join(dir, `fw${i}.conf`), v.text)
    writeFileSync(
      join(dir, `nginx${i}.conf`),
      harness.replace('/rules/8g-firewall.conf', `/x/fw${i}.conf`).replace('/tmp/nginx.pid', `/tmp/nginx${i}.pid`).replace('listen 8080', `listen ${9000 + i}`),
    )
    script.push(`nginx -t -q -c /x/nginx${i}.conf && nginx -c /x/nginx${i}.conf || echo "NOSTART ${i}"`)
  })
  script.push('sleep 0.3')
  // Send each request to stock nginx (port 9000) and to its edited copy. The shortened "1792..." is sent as 17920000:
  // nginx never saw the dots.
  cases.forEach((c, k) => {
    const l = c.r.line
    const target = l.requestUri!.replace(/([A-Za-z0-9]{4})\.\.\./g, '$10000')
    for (const port of [9000, 9001 + k]) {
      const parts = ['curl', '-s', '-o', '/dev/null', '-D', '-', l.method === 'HEAD' ? '-I' : `-X ${bytes(l.method!)}`, '--request-target', bytes(target)]
      parts.push('-H', l.userAgent ? bytes(`User-Agent: ${l.userAgent}`) : "'User-Agent:'")
      if (l.referer) parts.push('-H', bytes(`Referer: ${l.referer}`))
      parts.push(`http://127.0.0.1:${port}/`, `| tr -d '\\r' | grep -i '^x-ng-' | sed 's/^/${k} ${port} /'`)
      script.push(parts.join(' '))
    }
  })
  writeFileSync(join(dir, 'run.sh'), `${script.join('\n')}\n`)
  const out = run(['-v', `${dir}:/x:ro`, nginxImage, 'bash', '/x/run.sh'])
  assert.doesNotMatch(out, /NOSTART/)
  const got = (k: number, port: number) => {
    const h: Record<string, number> = {}
    for (const m of out.matchAll(new RegExp(`^${k} ${port} x-ng-(\\w+): (\\d+)$`, 'gim'))) h[m[1].toLowerCase()] = Number(m[2])
    return HEADERS.map((id) => h[groups.get(id)!.field] ?? -1)
  }
  cases.forEach((c, k) => {
    const stock = got(k, 9000)
    const edited = got(k, 9001 + k)
    const gi = HEADERS.indexOf(c.plan.group.id)
    assert.ok(stock[gi] > 0, `${c.name}: stock 8G matches (${stock})`)
    assert.equal(edited[gi], 0, `${c.name}: after the edit, ${c.plan.group.field} is 0`)
    HEADERS.forEach((id, i) => {
      if (i !== gi) assert.equal(edited[i], stock[i], `${c.name}: ${id} is untouched`)
    })
  })
  // The Mozlila line still hits request rule 42 after its bot edit: the warning the plan gives.
  const m = cases.findIndex((c) => c.name === 'Mozlila')
  assert.equal(got(m, 9001 + m)[HEADERS.indexOf('bad_request')], 42)
})

// Make sure the rule list used above is the real one.
test('the plans name rules by the file they came from', () => {
  const r: Rule = groups.get('bad_bot')!.rules[2]
  assert.equal(ruleText(r), r.sourceLine.trim())
})
