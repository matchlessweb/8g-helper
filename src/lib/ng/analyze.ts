// From pasted text to one result per log line.

import { parseLogLine, splitLines, type LogLine } from './logline.ts'
import { matchLine, type GroupResult } from './match.ts'
import type { GroupId, Rule, RuleGroup } from './rules.ts'
import { judge, type Verdict } from './verdict.ts'

/**
 * enforce: 8G answered this request itself (403, or 405 for a method rule).
 * watch:   8G only logged what it would block; something else answered (7G stayed on, the site served it).
 * unknown: the line cannot say (an access log line).
 */
export type Mode = 'enforce' | 'watch' | 'unknown'

/** The rule 8G acts on for this request: the first non-zero group in 8g.conf's order, and its number. */
export interface Fired {
  group: RuleGroup
  number: number
  /** undefined when 8G v1.5 has no rule with that number in the group. */
  rule?: Rule
  /** 'log': the line logged it. 'match': the line logged nothing (an access log), so it is what 8G would do. */
  from: 'log' | 'match'
}

export type LineResult =
  | {
      ok: true
      line: LogLine
      /** All six groups in 8g.conf's check order (cookie, method, referer, bot, querystring, request). */
      groups: GroupResult[]
      fired?: Fired
      mode: Mode
      /** Set when nothing fired: why the request was not 8G's to block, in plain words. */
      nothing?: string
      /** Set when something fired. */
      verdict?: Verdict
    }
  | { ok: false; raw: string; reason: string }

function firedRule(line: LogLine, groups: GroupResult[]): Fired | undefined {
  if (line.format !== 'combined') {
    const g = groups.find((x) => x.logged)
    if (g) return { group: g.group, number: g.logged!, rule: g.loggedRule, from: 'log' }
    if (line.format === 'ng8') return undefined
  }
  for (const g of groups) {
    const m = g.matches.find((x) => x.first)
    if (m) return { group: g.group, number: m.rule.number, rule: m.rule, from: 'match' }
  }
  return undefined
}

function modeOf(line: LogLine, fired: Fired | undefined): Mode {
  if (line.format === 'combined') return 'unknown'
  // 8g.conf sets $ng_reason only on the way to returning 403 or 405.
  if (line.format === 'ng_reason') return 'enforce'
  if (!fired) return 'unknown'
  return line.status === String(fired.group.status) ? 'enforce' : 'watch'
}

function nothingReason(line: LogLine): string {
  if (line.format === 'ng8') return 'Every group logged 0, so 8G matched nothing in this request.'
  switch (line.status) {
    case '403':
      return 'No 8G rule matches this request, so the 403 came from somewhere else: 7G (it runs first on GridPane), a security plugin, WordPress itself, or Cloudflare.'
    case '405':
      return 'No 8G rule matches this request. The 405 came from nginx itself (it refuses TRACE before 8G runs), from the site, or from another rule.'
    case '444':
      return 'No 8G rule matches this request. nginx closed the connection (444) because of another rule on the server, such as GridPane’s own XML-RPC block.'
    default:
      return 'No 8G rule matches this request: 8G lets it through.'
  }
}

export function analyzeLine(raw: string, groups: Map<GroupId, RuleGroup>): LineResult {
  const parsed = parseLogLine(raw)
  if (!parsed.ok) return parsed
  const line = parsed.line
  const results = matchLine(line, groups)
  const fired = firedRule(line, results)
  const mode = modeOf(line, fired)
  if (!fired) return { ok: true, line, groups: results, mode, nothing: nothingReason(line) }
  return { ok: true, line, groups: results, fired, mode, verdict: judge(line, results) }
}

export function analyze(text: string, groups: Map<GroupId, RuleGroup>): LineResult[] {
  return splitLines(text).map((raw) => analyzeLine(raw, groups))
}
