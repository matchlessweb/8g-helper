// "Allow it for now": nG's documented way to let a false positive through, until scoped per-site exceptions exist.
// Comment out the rule's line in 8g-firewall.conf, or delete just the name that matched (Jeff Starr's advice for
// Ahrefs: delete ahrefs| from bot rule 3).
//
// nginx keeps one set of maps per server: the copy of 8g-firewall.conf it loads last applies to every site that runs
// 8G there. On GridPane each site has its own copy (/var/www/<site>/nginx/8g/8g-firewall.conf), so every copy on the
// server gets the same edit. House rule from 7G: never edit through a glob. First a read-only command lists each copy
// with the line number of each rule (grep -nF); the edit then names those files and lines, backs each file up, checks
// every changed line, and reloads only if nginx -t passes, putting the backups back if anything fails.

import { cutSpans } from './logline.ts'
import { matchOutsideCuts, type GroupResult } from './match.ts'
import { compilePcre, hasEmptyAlternative, isNameLike, removals } from './pcre.ts'
import { nginxUnquote, nginxUnquoteMapped, type InputName, type Rule, type RuleGroup } from './rules.ts'

export interface AllowEdit {
  rule: Rule
  /** remove: take names out of the rule. comment: put # in front of the whole rule. */
  kind: 'remove' | 'comment'
  /** The names taken out, as the file spells them, in the order they were taken out. Empty for comment. */
  tokens: string[]
  /** The rule's line without its leading whitespace, before and after the edit. */
  before: string
  after: string
}

export type AllowWarningCode =
  | 'server_wide'
  | 'update'
  | 'token_everywhere'
  | 'rule_off'
  | 'other_rules'
  | 'other_groups'
  | 'whole_rule'
  | 'shortened'

export interface AllowWarning {
  code: AllowWarningCode
  text: string
}

export interface AllowPlan {
  group: RuleGroup
  /** The value the plan was made for. undefined when the line does not carry it: then the logged rule is commented out. */
  value?: string
  /** In file order. Empty when no rule in the group matches. */
  edits: AllowEdit[]
  warnings: AllowWarning[]
}

const WHAT: Record<InputName, string> = {
  http_cookie: 'cookie',
  request_method: 'request method',
  http_referer: 'referrer',
  http_user_agent: 'user agent',
  query_string: 'query string',
  uri: 'address',
}

const PART: Record<InputName, string> = {
  http_cookie: 'cookies',
  request_method: 'request method',
  http_referer: 'referrer',
  http_user_agent: 'user agent',
  query_string: 'query string',
  uri: 'address',
}

/** The rule's line as written, minus its indentation: "~*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3; */
export function ruleText(rule: Rule): string {
  return rule.sourceLine.replace(/^\s+/, '')
}

interface Working {
  rule: Rule
  source: string
  pattern: string
  tokens: string[]
  comment: boolean
}

/** Take one alternative out of a working rule, in the pattern and in the file's spelling, and prove they agree. */
function takeOut(w: Working, start: number, end: number, altStart: number, altEnd: number): void {
  const { text, map } = nginxUnquoteMapped(w.source)
  if (text !== w.pattern) throw new Error(`rule ${w.rule.number}: source and pattern disagree`)
  const token = w.source.slice(map[altStart], map[altEnd])
  const source = w.source.slice(0, map[start]) + w.source.slice(map[end])
  const pattern = w.pattern.slice(0, start) + w.pattern.slice(end)
  if (nginxUnquote(source) !== pattern || hasEmptyAlternative(pattern)) {
    throw new Error(`rule ${w.rule.number}: taking out ${token} would break the pattern`)
  }
  w.tokens.push(token)
  w.source = source
  w.pattern = pattern
}

/**
 * The fewest names to take out (or, where a rule is not a list of names, the rules to comment out) so that no rule in
 * the group matches value any more. nginx's map moves on to the next rule when one stops matching, so a request
 * that two rules match needs both edited: Stripe's MerchantSecurityScanner hits "scan" in bot rules 3 and 11.
 * A match at text that was shortened before the line was pasted (abcd...) is not one nginx made, so it is ignored.
 */
export function editsFor(group: RuleGroup, value: string): AllowEdit[] {
  const cuts = cutSpans(value)
  const find = (pattern: string) => matchOutsideCuts(compilePcre(pattern), value, cuts)
  const working = new Map<number, Working>()
  const get = (rule: Rule): Working =>
    working.get(rule.number) ?? { rule, source: rule.source, pattern: rule.pattern, tokens: [], comment: false }

  for (let guard = 0; ; guard++) {
    if (guard > 500) throw new Error('allow plan did not settle')
    const hit = group.rules.map(get).find((w) => !w.comment && find(w.pattern))
    if (!hit) break
    working.set(hit.rule.number, hit)
    const m = find(hit.pattern)!
    const options = removals(hit.pattern)
      .filter((r) => isNameLike(r.text))
      .map((r) => {
        const next = find(hit.pattern.slice(0, r.start) + hit.pattern.slice(r.end))
        return { r, clears: !next, changes: !next || next.index !== m.index || next[0] !== m[0] }
      })
      .filter((o) => o.changes)
    const pick = options.find((o) => o.clears) ?? options[0]
    if (!pick) {
      hit.comment = true
      continue
    }
    takeOut(hit, pick.r.start, pick.r.end, pick.r.altStart, pick.r.altEnd)
  }

  return [...working.values()]
    .sort((a, b) => a.rule.line - b.rule.line)
    .map((w): AllowEdit => {
      const before = ruleText(w.rule)
      if (w.comment) return { rule: w.rule, kind: 'comment', tokens: [], before, after: `#${before}` }
      const quoted = `"~*${w.rule.source}"`
      if (!before.startsWith(quoted)) throw new Error(`rule ${w.rule.number}: unexpected line shape`)
      return { rule: w.rule, kind: 'remove', tokens: w.tokens, before, after: `"~*${w.source}"${before.slice(quoted.length)}` }
    })
}

const COMMON: AllowWarning[] = [
  {
    code: 'server_wide',
    text: 'This changes 8G for every site on this server, not only this one. nginx keeps one set of 8G rules per server, and the copy it loads last applies to every site, so the same edit goes into every copy.',
  },
  {
    code: 'update',
    text: 'An 8G update puts the rule back: the next download of 8g-firewall.conf replaces this edit. Check again after every update.',
  },
]

/** The interim fix for one group of a result. undefined when the group neither matched nor logged a rule. */
export function planAllow(g: GroupResult, others: GroupResult[] = []): AllowPlan | undefined {
  const field = g.group.field
  const warnings: AllowWarning[] = []
  let edits: AllowEdit[]

  // The log is the authority on what nginx did: a group it logged 0 for has nothing to allow.
  if (g.logged === 0) return undefined
  const unconfirmed = g.loggedRule !== undefined && g.check?.status !== 'confirmed'
  if (g.value !== undefined && g.matches.some((m) => m.first) && !unconfirmed) {
    edits = editsFor(g.group, g.value)
  } else if (g.loggedRule) {
    const rule = g.loggedRule
    edits = [{ rule, kind: 'comment', tokens: [], before: ruleText(rule), after: `#${ruleText(rule)}` }]
    warnings.push({
      code: 'whole_rule',
      text:
        g.value === undefined
          ? `The line does not carry the ${PART[g.group.input]}, so the whole of ${field} rule ${rule.number} is commented out rather than one name.`
          : `${field} rule ${rule.number} could not be matched against this request here, so the whole rule is commented out rather than one name.`,
    })
  } else {
    return undefined
  }

  for (const e of edits) {
    for (const t of e.tokens) {
      warnings.push({
        code: 'token_everywhere',
        text: `Taking “${t}” out of ${field} rule ${e.rule.number} lets every ${WHAT[g.group.input]} containing “${t}” through, on every site on the server, not only this request.`,
      })
    }
    if (e.kind === 'comment' && !warnings.some((w) => w.code === 'whole_rule')) {
      warnings.push({
        code: 'rule_off',
        text: `${field} rule ${e.rule.number} is not a list of names, so the whole rule is commented out. That turns it off for every request, on every site on the server.`,
      })
    }
  }
  if (g.value !== undefined && cutSpans(g.value).length) {
    warnings.push({
      code: 'shortened',
      text: 'Part of this line was shortened before it was pasted, so the edit is planned from the text the line shows. If the request is still logged after the edit, paste a full line from the log.',
    })
  }
  if (edits.length > 1) {
    warnings.push({
      code: 'other_rules',
      text: `${edits.length} rules in this group match this request (${edits.map((e) => e.rule.number).join(', ')}). nginx’s map moves on to the next one when a rule stops matching, so all of them are edited.`,
    })
  }
  const still = others.filter(
    (o) => o.group.id !== g.group.id && (o.logged !== undefined ? o.logged > 0 : o.matches.some((m) => m.first)),
  )
  for (const o of still) {
    const n = o.logged || o.matches.find((m) => m.first)?.rule.number
    warnings.push({
      code: 'other_groups',
      text: `This request also matches ${o.group.field} rule ${n}, so 8G still blocks it until that is allowed too.`,
    })
  }
  return { group: g.group, value: g.value, edits, warnings: [...warnings, ...COMMON] }
}

// Commands -----------------------------------------------------------------------------------------------------------

export const RELOAD = 'nginx -t && gp ngx reload'

/** Single-quoted for the shell. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

const COPIES =
  "{ nginx -T 2>/dev/null | sed -nE 's/^[[:space:]]*include[[:space:]]+([^;[:space:]]*8g-firewall\\.conf);.*$/\\1/p'; ls -1 /var/www/*/nginx/8g/8g-firewall.conf 2>/dev/null; } | sort -u"

/**
 * Read-only: every copy of 8g-firewall.conf nginx loads (from nginx -T) or a site folder holds, and the line number
 * of each rule in it. Prints file:line:text per rule found, and file:0:… for a copy that has none of them.
 */
export function findCopiesCommand(edits: AllowEdit[]): string {
  const patterns = edits.map((e) => `-e ${shellQuote(e.before)}`).join(' ')
  return `${COPIES} | while read -r f; do grep -HnF ${patterns} -- "$f" || echo "$f:0:none of these rules"; done`
}

export interface CopyListing {
  /** Each copy that has every rule as 8G v1.5 ships it, with the line number of each edit's rule (same order as edits). */
  copies: { file: string; lines: number[] }[]
  /** Reasons the edit cannot be built yet. Empty when every copy is ready. */
  problems: string[]
  /** Worth knowing, not blocking: line numbers that differ from 8G v1.5's. */
  notes: string[]
}

/** Read the output of findCopiesCommand, pasted back. */
export function parseCopies(output: string, edits: AllowEdit[]): CopyListing {
  const byFile = new Map<string, (number | undefined)[]>()
  const problems: string[] = []
  const notes: string[] = []
  const name = (e: AllowEdit) => `${e.rule.group.replace(/^bad_|^not_allowed_/, '')} rule ${e.rule.number}`

  for (const raw of output.split(/\r?\n/)) {
    const m = raw.match(/^(\/[^:]+):(\d+):(.*)$/)
    if (!m) continue
    const [, file, n, content] = m
    const lines = byFile.get(file) ?? edits.map(() => undefined)
    byFile.set(file, lines)
    if (n === '0') continue
    const text = content.replace(/^\s+/, '')
    edits.forEach((e, i) => {
      if (!text.includes(e.before)) return
      if (text === e.before) {
        if (lines[i] !== undefined) problems.push(`${file} has ${name(e)} twice (lines ${lines[i]} and ${n}). Check that copy by hand.`)
        lines[i] = Number(n)
      } else if (text.startsWith('#')) {
        problems.push(`${file}: ${name(e)} is already commented out (line ${n}).`)
      } else {
        problems.push(`${file} line ${n} has ${name(e)} with other text on the line. Check that copy by hand.`)
      }
    })
  }

  if (byFile.size === 0) problems.push('No copy of 8g-firewall.conf was found. Paste the whole output of the first command.')
  const copies: CopyListing['copies'] = []
  for (const [file, lines] of byFile) {
    const missing = edits.filter((_, i) => lines[i] === undefined)
    if (missing.length) {
      if (!problems.some((p) => p.startsWith(`${file}:`) || p.startsWith(`${file} `))) {
        problems.push(
          `${file} does not have ${missing.map(name).join(' or ')} as 8G v1.5 ships it: it was edited already, or it is another version. Make every copy the same first.`,
        )
      }
      continue
    }
    copies.push({ file, lines: lines as number[] })
    edits.forEach((e, i) => {
      if (lines[i] !== e.rule.line) notes.push(`${file}: ${name(e)} is on line ${lines[i]}, not ${e.rule.line} as in 8G v1.5. The copy may be another version.`)
    })
  }
  return { copies, problems, notes }
}

// A literal for a GNU sed basic regex: \ . * [ ^ $ are special; + ? | ( ) { } are literal unless escaped.
function bre(s: string): string {
  return s.replace(/[\\.*[^$]/g, '\\$&')
}

function delimiter(...texts: string[]): string {
  const d = ['#', '@', '!', ',', ':', '=', '%'].find((c) => texts.every((t) => !t.includes(c)))
  if (!d) throw new Error('no sed delimiter is free for this rule')
  return d
}

/** The sed expression for one edit on one line: changes that line only if it reads exactly as expected. */
export function sedExpression(e: AllowEdit, line: number): string {
  if (e.kind === 'comment') {
    const d = delimiter(e.before)
    return `${line}{\\${d}^[[:space:]]*${bre(e.before)}$${d}s/^\\([[:space:]]*\\)/\\1#/;}`
  }
  const d = delimiter(e.before, e.after)
  return `${line}s${d}^\\([[:space:]]*\\)${bre(e.before)}$${d}\\1${e.after.replace(/[\\&]/g, '\\$&')}${d}`
}

export interface AllowCommands {
  /** Backs up, edits every copy, checks each changed line, then nginx -t and reload; on any failure puts every copy back. */
  edit: string
  /** Read-only: shows each edited line in each copy. */
  verify: string
  /** Puts every copy back from its backup and reloads (to undo the edit later). */
  restore: string
  backupSuffix: string
}

/** Run in a subshell, so a STOP never closes the SSH session. */
export function buildAllowCommands(edits: AllowEdit[], copies: CopyListing['copies'], today: string): AllowCommands {
  if (!edits.length) throw new Error('nothing to edit')
  if (!copies.length) throw new Error('no copies to edit')
  if (copies.some((c) => c.lines.length !== edits.length || c.lines.some((n) => !(n > 0)))) {
    throw new Error('every copy needs a line number for every edit')
  }
  const suffix = `.bak-8g-helper-${today}`
  const files = copies.map((c) => shellQuote(c.file)).join(' ')
  const rules = edits.map((e) => `${e.rule.group.replace(/^bad_|^not_allowed_/, '')} rule ${e.rule.number}`).join(', ')

  const perFile = copies.map((c) => {
    const f = shellQuote(c.file)
    const sed = `sed -i ${edits.map((e, i) => `-e ${shellQuote(sedExpression(e, c.lines[i]))}`).join(' ')} ${f}`
    const checks = edits.map((e, i) => `[ "$(sed -n '${c.lines[i]}{s/^[[:space:]]*//;p}' ${f})" = ${shellQuote(e.after)} ]`)
    return `  { ${sed} && ${checks.join(' && ')}; } || { echo "FAILED: ${c.file} did not change as expected"; ok=0; }`
  })

  const edit = [
    '(',
    `  b=${suffix}`,
    `  set -- ${files}`,
    '  for f; do [ ! -e "$f$b" ] || { echo "STOP: $f$b already exists. Nothing was changed."; exit 1; }; done',
    '  for f; do cp -p "$f" "$f$b" || { echo "STOP: could not back up $f. Nothing was changed."; for g; do rm -f "$g$b"; done; exit 1; }; done',
    '  ok=1',
    ...perFile,
    '  if [ "$ok" = 1 ] && nginx -t; then',
    `    if gp ngx reload; then echo "DONE: ${rules} edited. Copies: $#. Backups end in $b"; else echo "FAILED: nginx -t passed but the reload did not. The edit is in place; run gp ngx reload again."; fi`,
    '  else',
    '    for f; do mv "$f$b" "$f"; done',
    '    echo "FAILED: every copy was put back from its backup, and nginx was not reloaded."',
    '  fi',
    ')',
  ].join('\n')

  const verify = `grep -HnF ${edits.map((e) => `-e ${shellQuote(e.after)}`).join(' ')} -- ${files}`
  const restore = [
    '(',
    `  b=${suffix}`,
    `  set -- ${files}`,
    '  for f; do [ -e "$f$b" ] || { echo "STOP: $f$b is missing. Nothing was changed."; exit 1; }; done',
    '  for f; do mv "$f$b" "$f"; done',
    `  ${RELOAD} && echo "DONE: every copy is back as it was before the edit."`,
    ')',
  ].join('\n')

  return { edit, verify, restore, backupSuffix: suffix }
}
