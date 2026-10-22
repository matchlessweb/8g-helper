// When the rule that fired is not GridPane's but an entry in the server's own list, the cleaner fix is often to take
// the crawler's name off that list. The lists are server-wide, so that fixes every site at once, and the other names
// on the line stay blocked. Seen on a real server: one custom line blocked facebookexternalhit with three AI crawlers.

import { botToken, buildException } from './exception.ts'
import type { LogLine } from './logline.ts'
import type { RuleMatch } from './match.ts'

export interface ListFix {
  /** The crawler's name as the list most likely spells it. */
  token: string
  /** Prints every entry with this number, with its file name, so nobody edits the wrong file. */
  find: string
  backup: string
  edit: string
  reload: string
  testAllowed: string
  testStillBlocked: string
}

const RELOAD = 'nginx -t && gp ngx reload'

/** grep for the entries numbered n, file name always shown (-H), even when only one file matches. */
export function findEntryCommand(m: RuleMatch): string {
  return `grep -HnE '[[:space:]]${m.hit.number};[[:space:]]*$' ${m.group.customInclude}`
}

/** A literal for a POSIX extended regex inside single quotes. Tokens are plain names, so only . and - can appear. */
function ere(s: string): string {
  return s.replace(/[.[\]*^$+?(){}|\\/]/g, '\\$&')
}

/**
 * The GNU sed that takes one name out of the entries numbered n, wherever it sits in the alternation, ignoring case
 * as the ~* map does. A line naming only that crawler is deleted whole: emptying it would leave ~*() 6, which
 * matches every request. A name spelled differently in the list is left alone, and the recheck shows it.
 */
export function removeCommand(token: string, n: number, files: string): string {
  const t = ere(token)
  const sp = '[[:space:]]'
  return [
    `sed -i -E '/${sp}${n};${sp}*$/{`,
    `/^${sp}*~\\*?\\(${t}\\)${sp}+${n};/Id;`,
    `s/\\|${t}\\|/|/I;`,
    `s/\\|${t}\\)/)/I;`,
    `s/\\(${t}\\|/(/I`,
    `}' ${files}`,
  ].join('')
}

/** Only for a crawler the log names plainly, when every rule that fired is a custom entry. */
export function buildListFix(line: LogLine, matches: RuleMatch[], today: string): ListFix | undefined {
  if (!matches.length || !matches.every((m) => m.status === 'custom' && m.hit.group === 'bad_bot')) return undefined
  if (!line.userAgent || new Set(matches.map((m) => m.hit.number)).size !== 1) return undefined
  const token = botToken(line.userAgent)
  if (!/^[a-z][\w.-]{2,39}$/i.test(token)) return undefined

  const m = matches[0]
  const files = m.group.customInclude
  const tests = buildException(line, matches, 'site', today)
  return {
    token,
    find: findEntryCommand(m),
    backup: `for f in ${files}; do cp "$f" "/root/$(basename "$f").bak-${today}"; done`,
    edit: removeCommand(token, m.hit.number, files),
    reload: RELOAD,
    testAllowed: tests.testAllowed,
    testStillBlocked: tests.testStillBlocked,
  }
}
