// Run every group's rules over the request, the way nginx's map does, and compare with what the line logged.
// An nginx map returns only its first matching regex, in file order, so every match is listed and the first is
// marked: that is the number nginx logs, and the rule 8G blocks on.

import { cutSpans, type LogLine } from './logline.ts'
import type { GroupId, InputName, Rule, RuleGroup } from './rules.ts'

export interface RuleMatch {
  group: RuleGroup
  rule: Rule
  /** The value the map tested, e.g. the user agent for bad_bot. A byte string; see printable(). */
  value: string
  /** Where the pattern matched inside value (the leftmost match, as PCRE finds it). */
  matched: { text: string; index: number }
  /** The first matching rule in the group: the one nginx's map returns, logs and blocks on. Never set on an inCut match. */
  first: boolean
  /**
   * Every match of this rule overlaps or touches text that was shortened before the line was pasted (abcd... or …).
   * nginx saw other text there, so the match may not be one nginx made. A rule that also matches clear of the
   * shortened text is not inCut, and matched shows that clear match.
   */
  inCut: boolean
}

export type CheckStatus =
  /** What the line logged for this group is what stock 8G v1.5 gives for this request. */
  | 'confirmed'
  /** It cannot be checked here: cookies are never logged, the line was shortened, or a part is missing. */
  | 'unchecked'
  /** It is not what stock 8G v1.5 gives: the server runs another version or an edited copy. */
  | 'mismatch'

export type CheckReason =
  | 'agrees'
  | 'cookie'
  | 'cut'
  | 'missing'
  | 'invalid_uri'
  | 'no_such_rule'
  | 'not_matched'
  | 'not_first'
  | 'unlogged_match'

export interface Check {
  status: CheckStatus
  reason: CheckReason
  /** One or two plain sentences for the page. */
  note: string
}

export interface GroupResult {
  group: RuleGroup
  /** The value this group's map read. undefined when the line does not carry it (cookies, always). */
  value?: string
  /** Every rule in the group that matches value, in file order. The first one has first: true. */
  matches: RuleMatch[]
  /** What the line says this group returned: 0 for no match. undefined when the line does not say. */
  logged?: number
  /** The rule with the logged number, when there is one in 8G v1.5. */
  loggedRule?: Rule
  /** Present whenever logged is known. */
  check?: Check
}

const PART: Record<InputName, string> = {
  http_cookie: 'cookie',
  request_method: 'request method',
  http_referer: 'referrer',
  http_user_agent: 'user agent',
  query_string: 'request',
  uri: 'request',
}

export function inputValue(line: LogLine, input: InputName): string | undefined {
  switch (input) {
    case 'http_cookie':
      return undefined
    case 'request_method':
      return line.method
    case 'http_referer':
      return line.referer
    case 'http_user_agent':
      return line.userAgent
    case 'query_string':
      return line.queryString
    case 'uri':
      return line.uri
  }
}

type Span = { start: number; end: number }

/**
 * The leftmost match of regex in value that neither overlaps nor touches shortened text, or null. Touching counts:
 * the four characters kept before the dots are real, but a \b or a lookaround at their edge read text nginx saw and
 * the line does not show. Each start position is tried with the leftmost match PCRE would find there; a different,
 * shorter alternative at the same position is not tried.
 */
export function matchOutsideCuts(regex: RegExp, value: string, cuts: Span[] = cutSpans(value)): RegExpExecArray | null {
  const touches = (m: RegExpExecArray) => cuts.some((c) => c.start <= m.index + m[0].length && c.end >= m.index)
  const m = regex.exec(value)
  if (!m || !cuts.length || !touches(m)) return m
  const sticky = new RegExp(regex.source, `${regex.flags.replace(/[gy]/g, '')}y`)
  for (let i = m.index + 1; i <= value.length; i++) {
    sticky.lastIndex = i
    const n = sticky.exec(value)
    if (n && !touches(n)) return n
  }
  return null
}

/** Every rule in the group that matches value, in file order, the first (clear of any shortened text) marked. */
export function matchGroup(group: RuleGroup, value: string): RuleMatch[] {
  const cuts = cutSpans(value)
  const out: RuleMatch[] = []
  for (const rule of group.rules) {
    const any = rule.regex.exec(value)
    if (!any) continue
    const clear = cuts.length ? matchOutsideCuts(rule.regex, value, cuts) : any
    const m = clear ?? any
    const inCut = !clear
    out.push({
      group,
      rule,
      value,
      matched: { text: m[0], index: m.index },
      first: !inCut && !out.some((x) => x.first),
      inCut,
    })
  }
  return out
}

/**
 * Whether shortened text hides part of what this group's map read. A cut in the path also hides whether a query
 * string followed it, so it affects the querystring group too; a cut in the query string leaves $uri alone.
 */
function cutAffects(line: LogLine, input: InputName): boolean {
  const has = (v?: string) => v !== undefined && cutSpans(v).length > 0
  switch (input) {
    case 'uri':
      return has(line.path)
    case 'query_string':
      return has(line.requestUri)
    case 'http_user_agent':
      return has(line.userAgent)
    case 'http_referer':
      return has(line.referer)
    default:
      return false
  }
}

function check(line: LogLine, g: Omit<GroupResult, 'check'>): Check | undefined {
  const logged = g.logged
  if (logged === undefined) return undefined
  const label = `${g.group.field} rule`
  const first = g.matches.find((m) => m.first)?.rule.number ?? 0
  const setAside = g.matches.filter((m) => m.inCut && m.rule.number !== logged)

  if (g.value === undefined) {
    if (g.group.id === 'bad_cookie') {
      return logged === 0
        ? { status: 'unchecked', reason: 'cookie', note: 'Cookies are not in the log line, so this group cannot be checked here.' }
        : {
            status: 'unchecked',
            reason: 'cookie',
            note: `Cookies are not in the log line, so ${label} ${logged} cannot be checked here. Its pattern is shown as logged.`,
          }
    }
    if (g.group.input === 'uri' && line.uriProblem && line.uriProblem.problem !== 'not_a_path') {
      return {
        status: 'unchecked',
        reason: 'invalid_uri',
        note: `nginx refuses this address with a 400 before 8G runs: ${line.uriProblem.reason}.`,
      }
    }
    return {
      status: 'unchecked',
      reason: 'missing',
      note: `The line does not include the ${PART[g.group.input]}, so ${logged ? `${label} ${logged}` : 'this group'} cannot be checked.`,
    }
  }

  if (logged === first) {
    const aside = setAside.length
      ? ` ${setAside.map((m) => `${label} ${m.rule.number}`).join(' and ')} matched only at the shortened part of the line (“${setAside[0].matched.text}”), where nginx saw other text, so ${setAside.length > 1 ? 'they were' : 'it was'} set aside.`
      : ''
    return {
      status: 'confirmed',
      reason: 'agrees',
      note: logged
        ? `${label} ${logged} matches this request and is the first in its group to match, as the log says.${aside}`
        : `No rule in this group matches, as the log says.${aside}`,
    }
  }

  if (cutAffects(line, g.group.input)) {
    return {
      status: 'unchecked',
      reason: 'cut',
      note: 'Part of this line was shortened before it was pasted, so the logged number cannot be checked against it.',
    }
  }

  if (logged === 0) {
    return {
      status: 'mismatch',
      reason: 'unlogged_match',
      note: `The log says 0 for this group, but ${label} ${first} matches. The server’s copy of 8g-firewall.conf may have that rule commented out or edited.`,
    }
  }
  if (!g.loggedRule) {
    return {
      status: 'mismatch',
      reason: 'no_such_rule',
      note: `8G v1.5 has no ${label} ${logged}. The server runs another version of 8G, or a rule of its own.`,
    }
  }
  if (g.matches.some((m) => m.rule.number === logged)) {
    return {
      status: 'mismatch',
      reason: 'not_first',
      note: `${label} ${logged} matches, but ${label} ${first} comes before it in the file and matches too, so stock 8G v1.5 would log ${first}. The server’s copy differs: rule ${first} may be edited or commented out.`,
    }
  }
  return {
    status: 'mismatch',
    reason: 'not_matched',
    note: `${label} ${logged} does not match this request here${first ? `; ${label} ${first} does` : ''}. The server’s copy of 8g-firewall.conf differs from 8G v1.5 (another version, or an edited rule).`,
  }
}

/** All six groups, in 8g.conf's check order, each with its matches and, where the line logged it, the check. */
export function matchLine(line: LogLine, groups: Map<GroupId, RuleGroup>): GroupResult[] {
  return [...groups.values()].map((group) => {
    const value = inputValue(line, group.input)
    const logged = line.logged[group.id]
    const r: Omit<GroupResult, 'check'> = {
      group,
      value,
      matches: value === undefined ? [] : matchGroup(group, value),
      logged,
      loggedRule: logged ? group.rules.find((x) => x.number === logged) : undefined,
    }
    return { ...r, check: check(line, r) }
  })
}
