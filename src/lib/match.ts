// For each rule a log line names, find that rule in the shipped maps and show what it matched.

import type { Hit, LogLine } from './logline.ts'
import type { GroupId, InputName, Rule, RuleGroup } from './rules.ts'

export type MatchStatus =
  /** The logged rule is in GridPane's shipped list, and it matches this request. */
  | 'matched'
  /** The logged number is not in the shipped list: it came from a custom list on the server. */
  | 'custom'
  /** The logged rule is in the shipped list but does not match here: the server's copy differs, or a custom entry reused the number. */
  | 'unverified'

export interface RuleMatch {
  hit: Hit
  group: RuleGroup
  status: MatchStatus
  rule?: Rule
  /** The value the map tested, e.g. the user agent for bad_bot. */
  value: string
  /** Where the pattern matched inside value. */
  matched?: { text: string; index: number }
}

export function inputValue(line: LogLine, input: InputName): string {
  switch (input) {
    case 'http_user_agent':
      return line.userAgent
    case 'http_referer':
      return line.referer
    case 'query_string':
      return line.queryString
    case 'request_uri':
      return line.uri
    case 'request_method':
      return line.method
  }
}

export function matchLine(line: LogLine, groups: Map<GroupId, RuleGroup>): RuleMatch[] {
  return line.hits.map((hit) => {
    const group = groups.get(hit.group)!
    const value = inputValue(line, group.input)
    const rule = group.rules.find((r) => r.number === hit.number)
    if (!rule) return { hit, group, status: 'custom', value }
    const m = rule.regex.exec(value)
    if (!m) return { hit, group, status: 'unverified', rule, value }
    return { hit, group, status: 'matched', rule, value, matched: { text: m[0], index: m.index } }
  })
}
