// The 8G accuracy harness. Every request in test/fixtures/8g-*.txt, plus the edge cases below, is sent through real
// nginx in Docker with 8g-firewall.conf loaded (test/nginx/nginx.conf), raw: method, request target byte for byte,
// user agent, referrer and cookie. nginx answers with the first match of each of the six maps and its own $uri and
// $query_string. The harness compares those, group by group, with the JavaScript matcher, and with the numbers a log
// line carries. Any disagreement fails the run. Run it with: bash test/nginx/run.sh

import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseLogLine, splitLines } from '../../src/lib/ng/logline.ts'
import { CHECK_ORDER, parseFirewall, type GroupId, type RuleGroup } from '../../src/lib/ng/rules.ts'
import { normalizeUri, splitRequestUri, type NormalizedUri } from '../../src/lib/ng/uri.ts'

const root = new URL('../../', import.meta.url).pathname
const args = process.argv.slice(2)
const opt = (name: string): string | undefined => {
  const i = args.indexOf(name)
  return i === -1 ? undefined : args[i + 1]
}
const image = opt('--image') ?? 'nginx:1.27'
const broken = opt('--break')
const verbose = args.includes('--verbose')
if (broken && broken !== 'uri' && broken !== 'pcre') throw new Error('--break takes uri or pcre')

const groups = parseFirewall(readFileSync(join(root, 'rules/8g-firewall.conf'), 'utf8'))
/** Fixture lines the parser could not read: each one fails the run, so no case is skipped silently. */
const unreadable: string[] = []

interface Case {
  id: number
  from: string
  method: string
  /** The raw request target, a byte string. */
  target: string
  /** undefined: no header sent. */
  ua?: string
  referer?: string
  cookie?: string
  /** What the log line says nginx returned, when it is an 8G log line. */
  logged?: Partial<Record<GroupId, number>>
  cut?: boolean
}

// Edge cases that are not log lines: cookies (never logged), addresses nginx refuses with 400, fragments, odd bytes.
const EXTRA: Omit<Case, 'id' | 'from'>[] = [
  { method: 'GET', target: '/', cookie: 'session=abc123' },
  { method: 'GET', target: '/', cookie: 'pref=<b>' },
  { method: 'GET', target: '/', cookie: 'q=%27x' },
  { method: 'GET', target: '/', cookie: "a='1'" },
  { method: 'GET', target: '/', cookie: 'a=%0A' },
  { method: 'GET', target: '/a%zz' },
  { method: 'GET', target: '/a%' },
  { method: 'GET', target: '/a%2' },
  { method: 'GET', target: '/a%00b' },
  { method: 'GET', target: '/../etc/passwd' },
  { method: 'GET', target: '/a/../../x' },
  { method: 'GET', target: '/%2e%2e/x' },
  { method: 'GET', target: '/a/%2e%2e/%2e%2e/x' },
  { method: 'GET', target: '/..' },
  { method: 'GET', target: '/a/..' },
  { method: 'GET', target: '/a/.' },
  { method: 'GET', target: '/a/.%2e/b' },
  { method: 'GET', target: '/a/..%2fb' },
  { method: 'GET', target: '/a%2f%2f%2fb' },
  { method: 'GET', target: '/a/%2f/b' },
  { method: 'GET', target: '/%25' },
  { method: 'GET', target: '/%2541' },
  { method: 'GET', target: '/a%23b' },
  { method: 'GET', target: '/a%3fb?c=1' },
  { method: 'GET', target: '/A/B/../C' },
  { method: 'GET', target: '/x/%2E%2E/.ENV' },
  { method: 'GET', target: '/ok#/.env' },
  { method: 'GET', target: '/ok?x=1#/etc/passwd' },
  { method: 'GET', target: '/ok#x?y=etc/passwd' },
  { method: 'GET', target: '/?' },
  { method: 'GET', target: '/a?b?c=..%2f' },
  { method: 'GET', target: '/a+b%20c' },
  { method: 'GET', target: '/x\\y' },
  { method: 'GET', target: '/a"b' },
  { method: 'GET', target: '/a<b>' },
  { method: 'GET', target: "/a'b/" },
  { method: 'GET', target: '/\xC3\xA9t\xC3\xA9/' },
  { method: 'GET', target: '/', ua: '-', referer: '-' },
  { method: 'GET', target: '/', ua: 'a' },
  { method: 'GET', target: '/', ua: 'Mozilla/5.0 (compatible; Barkrowler/0.9; +https://babbar.tech/crawler)' },
  { method: 'TRACE', target: '/' },
  { method: 'TRACK', target: '/' },
]

function collect(): Case[] {
  const cases: Case[] = []
  const dir = join(root, 'test/fixtures')
  for (const file of readdirSync(dir).filter((f) => /^8g-.*\.txt$/.test(f)).sort()) {
    for (const raw of splitLines(readFileSync(join(dir, file), 'utf8'))) {
      const p = parseLogLine(raw)
      if (!p.ok || p.line.method === undefined || p.line.requestUri === undefined) {
        unreadable.push(`${file}: ${p.ok ? 'no request in the line' : p.reason}: ${raw.slice(0, 80)}`)
        continue
      }
      const l = p.line
      cases.push({
        id: cases.length,
        from: file,
        method: l.method!,
        target: l.requestUri!,
        ua: l.userAgent || undefined,
        referer: l.referer || undefined,
        logged: l.format === 'ng8' ? l.logged : undefined,
        cut: l.cut,
      })
    }
  }
  for (const c of EXTRA) cases.push({ ...c, id: cases.length, from: 'harness' })
  return cases
}

// The deliberately wrong versions, to prove the harness can fail.
const brokenUri = (path: string): NormalizedUri => ({ ok: true, uri: path.split('#')[0] })
const regexOf = (g: RuleGroup, i: number): RegExp =>
  broken === 'pcre' ? new RegExp(g.rules[i].pattern, 'i') : g.rules[i].regex

/** What nginx should answer, by the JavaScript side: the first raw match per group (no cut handling: nginx sees the text as sent). */
function expected(c: Case) {
  const t = splitRequestUri(c.target)
  const uri = broken === 'uri' ? brokenUri(t.path) : normalizeUri(t.path)
  const values: Record<GroupId, string | undefined> = {
    bad_cookie: c.cookie ?? '',
    not_allowed_method: c.method,
    bad_referer: c.referer ?? '',
    bad_bot: c.ua ?? '',
    bad_querystring: t.queryString,
    bad_request: uri.ok ? uri.uri : undefined,
  }
  const first = {} as Record<GroupId, number>
  for (const id of CHECK_ORDER) {
    const g = groups.get(id)!
    const v = values[id]
    const i = v === undefined ? -1 : g.rules.findIndex((_, k) => regexOf(g, k).test(v))
    first[id] = i === -1 ? 0 : g.rules[i].number
  }
  return { uri, queryString: t.queryString, first }
}

/** A bash $'…' word holding these exact bytes. */
const bytes = (s: string): string =>
  `$'${[...s].map((ch) => (/[A-Za-z0-9/._,:;=+-]/.test(ch) ? ch : `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`)).join('')}'`

function script(cases: Case[]): string {
  const lines = [
    'set -u',
    'nginx -v 2>&1 | sed "s/^/VERSION /"',
    'nginx || exit 1',
    'for i in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:8080/ && break; sleep 0.1; done',
    'mkdir -p /work/out',
  ]
  for (const c of cases) {
    const parts = ['curl', '-s', '--max-time', '5', '-o', `/work/out/${c.id}.body`, '-D', `/work/out/${c.id}.head`]
    parts.push(c.method === 'HEAD' ? '-I' : `-X ${bytes(c.method)}`)
    parts.push('--request-target', bytes(c.target))
    parts.push('-H', c.ua === undefined ? "'User-Agent:'" : bytes(`User-Agent: ${c.ua}`))
    if (c.referer !== undefined) parts.push('-H', bytes(`Referer: ${c.referer}`))
    if (c.cookie !== undefined) parts.push('-H', bytes(`Cookie: ${c.cookie}`))
    parts.push('http://127.0.0.1:8080/')
    lines.push(`${parts.join(' ')} >/dev/null; echo "${c.id} $?" >> /work/out/exit`)
  }
  return `${lines.join('\n')}\n`
}

const HEADER: Record<GroupId, string> = {
  bad_cookie: 'x-ng-cookie',
  not_allowed_method: 'x-ng-method',
  bad_referer: 'x-ng-referer',
  bad_bot: 'x-ng-bot',
  bad_querystring: 'x-ng-querystring',
  bad_request: 'x-ng-request',
}

function main(): void {
  if (spawnSync('docker', ['info'], { stdio: 'ignore' }).status !== 0) {
    console.error('Docker is not running: the nginx harness cannot run.')
    process.exit(2)
  }
  const cases = collect()
  const work = mkdtempSync(join(tmpdir(), 'ng-harness-'))
  mkdirSync(join(work, 'out'))
  writeFileSync(join(work, 'cases.sh'), script(cases))
  const run = execFileSync(
    'docker',
    [
      'run', '--rm',
      '-v', `${join(root, 'test/nginx/nginx.conf')}:/etc/nginx/nginx.conf:ro`,
      '-v', `${join(root, 'rules')}:/rules:ro`,
      '-v', `${work}:/work`,
      image, 'bash', '/work/cases.sh',
    ],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  )
  const version = run.match(/^VERSION (.*)$/m)?.[1] ?? 'unknown'

  const problems: string[] = unreadable.map((u) => `unreadable fixture line: ${u}`)
  let groupChecks = 0
  let valueChecks = 0
  let loggedChecks = 0
  let refused = 0
  let skippedLogged = 0

  for (const c of cases) {
    const head = readFileSync(join(work, 'out', `${c.id}.head`), 'latin1')
    const status = Number(head.match(/^HTTP\/[\d.]+ (\d{3})/)?.[1])
    const headers = Object.fromEntries(
      [...head.matchAll(/^([A-Za-z-]+): ?(.*?)\r?$/gm)].map((m) => [m[1].toLowerCase(), m[2]]),
    )
    const exp = expected(c)
    const label = `#${c.id} ${c.from} ${c.method} ${JSON.stringify(c.target)}`
    const say = (what: string) => problems.push(`${label}: ${what}`)

    if (c.method === 'TRACE') {
      if (status !== 405) say(`nginx answered ${status}, expected its own 405 for TRACE`)
      refused++
      if (verbose) console.log(`${label} -> ${status} (nginx refuses TRACE before any map)`)
      continue
    }
    if (!exp.uri.ok && exp.uri.problem !== 'not_a_path') {
      if (status !== 400) say(`JavaScript says nginx refuses it (${exp.uri.problem}), but nginx answered ${status}`)
      refused++
      if (verbose) console.log(`${label} -> ${status} (${exp.uri.problem})`)
      continue
    }
    if (status !== 200) {
      say(`nginx answered ${status}; JavaScript built $uri ${JSON.stringify(exp.uri.ok ? exp.uri.uri : exp.uri.problem)}`)
      continue
    }

    const got = {} as Record<GroupId, number>
    for (const id of CHECK_ORDER) {
      got[id] = Number(headers[HEADER[id]])
      groupChecks++
      if (got[id] !== exp.first[id]) say(`${id}: nginx ${got[id]}, JavaScript ${exp.first[id]}`)
    }
    if (c.method !== 'HEAD') {
      const body = readFileSync(join(work, 'out', `${c.id}.body`), 'latin1')
      const m = body.match(/^<uri>([\s\S]*)<\/uri><qs>([\s\S]*)<\/qs>$/)
      valueChecks++
      if (!m) say(`unexpected body ${JSON.stringify(body.slice(0, 80))}`)
      else {
        if (exp.uri.ok && m[1] !== exp.uri.uri) say(`$uri: nginx ${JSON.stringify(m[1])}, JavaScript ${JSON.stringify(exp.uri.uri)}`)
        if (m[2] !== exp.queryString) say(`$query_string: nginx ${JSON.stringify(m[2])}, JavaScript ${JSON.stringify(exp.queryString)}`)
      }
    }
    if (c.logged) {
      if (c.cut) skippedLogged++
      for (const id of CHECK_ORDER) {
        // Cookies are never in the line, and a shortened line is not the request nginx saw.
        if (c.cut || id === 'bad_cookie') continue
        loggedChecks++
        if (c.logged[id] !== got[id]) say(`${id}: the log line says ${c.logged[id]}, nginx gives ${got[id]}`)
      }
    }
    if (verbose) console.log(`${label} -> ${CHECK_ORDER.map((id) => `${HEADER[id].slice(5)}=${got[id]}`).join(' ')}`)
  }

  console.log(`nginx: ${version} (${image})${broken ? `, deliberately broken: ${broken}` : ''}`)
  console.log(
    `${cases.length} requests: ${groupChecks} group results compared, ${valueChecks} $uri/$query_string pairs, ${loggedChecks} logged numbers, ${refused} refused by nginx itself (400, or 405 for TRACE)${skippedLogged ? `; logged numbers not compared on ${skippedLogged} shortened line(s)` : ''}.`,
  )
  if (problems.length) {
    console.log(`\n${problems.length} disagreement(s):`)
    for (const p of problems) console.log(`  ${p}`)
    process.exit(1)
  }
  console.log('Every case agrees.')
}

main()
