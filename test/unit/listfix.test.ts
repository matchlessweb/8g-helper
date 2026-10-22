import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { analyze } from '../../src/lib/analyze.ts'
import { buildListFix, removeCommand } from '../../src/lib/listfix.ts'
import { parseMappings } from '../../src/lib/rules.ts'

const root = new URL('../../', import.meta.url)
const groups = parseMappings(readFileSync(new URL('rules/gridpane-7g-mappings.conf', root), 'utf8'))
const samples = readFileSync(new URL('test/fixtures/7g-log-samples.txt', root), 'utf8').split('\n').filter(Boolean)
const first = (raw: string) => {
  const [r] = analyze(raw, groups)
  assert.ok(r.ok)
  return r
}
const facebook = first(samples.find((l) => l.includes('facebookexternalhit'))!)
const gptbot = first(samples.find((l) => l.includes('GPTBot'))!)
const rankmath = first(samples.find((l) => l.includes('rankmath'))!)

test('a custom bad_bot rule gets a list fix named for the crawler', () => {
  const fix = buildListFix(facebook.line, facebook.matches, '2026-10-21')!
  assert.equal(fix.token, 'facebookexternalhit')
  assert.equal(fix.find, "grep -HnE '[[:space:]]6;[[:space:]]*$' /etc/nginx/extra.d/*7g-bad-bot-context.conf")
  assert.match(fix.backup, /^for f in \/etc\/nginx\/extra\.d\/\*7g-bad-bot-context\.conf; do cp "\$f" "\/root\//)
  assert.equal(buildListFix(gptbot.line, gptbot.matches, '2026-10-21')!.token, 'GPTBot')
})

test('no list fix for a shipped rule', () => {
  assert.equal(buildListFix(rankmath.line, rankmath.matches, '2026-10-21'), undefined)
})

// The edit runs on a GridPane server, so prove it with GNU sed, not the BSD sed on a Mac.
const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0

const HEADER = '# #\n# GridPane Server 7G WAF Bad Bot mapping include\n# Version 1.2.0\n# #\n'
const CASES: [string, string, string][] = [
  ['last member', '~*(GPTBot|meta-externalagent|FacebookBot|facebookexternalhit) 6;', '~*(GPTBot|meta-externalagent|FacebookBot) 6;'],
  ['first member', '~*(facebookexternalhit|GPTBot) 6;', '~*(GPTBot) 6;'],
  ['middle member', '~*(GPTBot|facebookexternalhit|FacebookBot) 6;', '~*(GPTBot|FacebookBot) 6;'],
  ['sole member: the line goes, never ~*() 6', '~*(facebookexternalhit) 6;', ''],
  ['other case in the list', '~*(GPTBot|FacebookExternalHit) 6;', '~*(GPTBot) 6;'],
  ['another number is left alone', '~*(facebookexternalhit|GPTBot) 7;', '~*(facebookexternalhit|GPTBot) 7;'],
  ['a longer name is left alone', '~*(GPTBot|facebookexternalhitx) 6;', '~*(GPTBot|facebookexternalhitx) 6;'],
]

test('the sed takes only that name out, with GNU sed, across two list files', { skip: !docker && 'docker is not running' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'listfix-'))
  CASES.forEach(([, before], i) => writeFileSync(join(dir, `c${i}-7g-bad-bot-context.conf`), `${HEADER}${before}\n`))
  writeFileSync(join(dir, 'gridpane-7g-bad-bot-context.conf'), HEADER)
  const cmd = removeCommand('facebookexternalhit', 6, '/x/*7g-bad-bot-context.conf')
  execFileSync('docker', ['run', '--rm', '-v', `${dir}:/x`, 'debian:stable-slim', 'sh', '-c', cmd])
  CASES.forEach(([name, , after], i) => {
    assert.equal(readFileSync(join(dir, `c${i}-7g-bad-bot-context.conf`), 'utf8'), `${HEADER}${after ? `${after}\n` : ''}`, name)
  })
  assert.equal(readFileSync(join(dir, 'gridpane-7g-bad-bot-context.conf'), 'utf8'), HEADER, 'a list without the entry is unchanged')
})

test('the find command names the file even when one file matches', { skip: !docker && 'docker is not running' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'listfind-'))
  writeFileSync(join(dir, 'gridpane-7g-bad-bot-context.conf'), HEADER)
  writeFileSync(join(dir, 'blockbots-7g-bad-bot-context.conf'), '~*(GPTBot|facebookexternalhit) 6;\n')
  const fix = buildListFix(facebook.line, facebook.matches, '2026-10-21')!
  const cmd = fix.find.replace('/etc/nginx/extra.d/', '/x/')
  const out = execFileSync('docker', ['run', '--rm', '-v', `${dir}:/x`, 'debian:stable-slim', 'sh', '-c', cmd], { encoding: 'utf8' })
  assert.equal(out, '/x/blockbots-7g-bad-bot-context.conf:1:~*(GPTBot|facebookexternalhit) 6;\n')
})
