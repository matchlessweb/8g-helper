// From pasted text to one result per log line.

import { parseLogLine, splitLines, type LogLine } from './logline.ts'
import { matchLine, type RuleMatch } from './match.ts'
import type { GroupId, RuleGroup } from './rules.ts'
import { judge, type Verdict } from './verdict.ts'

export type LineResult =
  | { ok: true; line: LogLine; matches: RuleMatch[]; verdict: Verdict }
  | { ok: false; raw: string; reason: string }

export function analyze(text: string, groups: Map<GroupId, RuleGroup>): LineResult[] {
  return splitLines(text).map((raw) => {
    const parsed = parseLogLine(raw)
    if (!parsed.ok) return parsed
    const matches = matchLine(parsed.line, groups)
    return { ok: true, line: parsed.line, matches, verdict: judge(parsed.line, matches) }
  })
}
