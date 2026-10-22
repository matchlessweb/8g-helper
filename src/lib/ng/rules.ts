// 8G's maps, read from the shipped file (rules/8g-firewall.conf: nG-SetEnvIf, "8G FIREWALL v1.5 20251006", commit
// 344d9c4, GPL-3.0). The file is parsed as nginx reads it, line by line, and any line it does not understand throws.

import { parsePcre, type PcreDifference } from './pcre.ts'

export type GroupId = 'bad_cookie' | 'not_allowed_method' | 'bad_referer' | 'bad_bot' | 'bad_querystring' | 'bad_request'

/** The nginx variable each map reads. $uri is the decoded, normalized path; $query_string is raw. */
export type InputName = 'http_cookie' | 'request_method' | 'http_referer' | 'http_user_agent' | 'query_string' | 'uri'

/** The short name our 8G log line uses for each group: cookie=0 method=0 referer=0 bot=3 querystring=0 request=0. */
export type FieldName = 'cookie' | 'method' | 'referer' | 'bot' | 'querystring' | 'request'

export interface Rule {
  group: GroupId
  number: number
  /** 1-based line number in 8g-firewall.conf. */
  line: number
  /** The whole line exactly as the file has it, leading tab included. */
  sourceLine: string
  /** The pattern as written in the file, inside its quotes, without the ~*. */
  source: string
  /** The pattern after nginx's own unquoting: what PCRE compiles. */
  pattern: string
  /** The pattern compiled for JavaScript, case-insensitive (nginx ~*), with PCRE's meaning kept (see pcre.ts). */
  regex: RegExp
  /** PCRE constructs in this pattern that JavaScript reads differently, translated in regex. */
  differences: PcreDifference[]
}

export interface RuleGroup {
  id: GroupId
  field: FieldName
  /** The map's output variable, e.g. bad_bot_ng. */
  variable: string
  /** The nginx variable the map reads, e.g. http_user_agent. */
  input: InputName
  /** Position in 8g.conf's check order: cookie 0, method 1, referer 2, bot 3, querystring 4, request 5. */
  order: number
  /** What 8g.conf returns when this group is the first to match. */
  status: 403 | 405
  /** 1-based line of the map's opening line. */
  line: number
  rules: Rule[]
}

export const RULESET_SOURCE = {
  name: 'nG-SetEnvIf',
  title: '8G Firewall for nginx',
  version: '1.5',
  header: '# 8G FIREWALL v1.5 20251006',
  repo: 'https://github.com/t18d/nG-SetEnvIf',
  commit: '344d9c417c02cf065d997059c7491100d0c96797',
  license: 'GPL-3.0',
  /** Where the GridPane runbook puts each site's copy. */
  path: '/var/www/<site>/nginx/8g/8g-firewall.conf',
}

/** 8g.conf checks the groups in this order; the first non-zero one sets $ng_reason and returns. */
export const CHECK_ORDER: readonly GroupId[] = [
  'bad_cookie',
  'not_allowed_method',
  'bad_referer',
  'bad_bot',
  'bad_querystring',
  'bad_request',
]

const GROUP_BY_VARIABLE: Record<string, { id: GroupId; field: FieldName; input: InputName; status: 403 | 405 }> = {
  bad_cookie_ng: { id: 'bad_cookie', field: 'cookie', input: 'http_cookie', status: 403 },
  not_allowed_method_ng: { id: 'not_allowed_method', field: 'method', input: 'request_method', status: 405 },
  bad_referer_ng: { id: 'bad_referer', field: 'referer', input: 'http_referer', status: 403 },
  bad_bot_ng: { id: 'bad_bot', field: 'bot', input: 'http_user_agent', status: 403 },
  bad_querystring_ng: { id: 'bad_querystring', field: 'querystring', input: 'query_string', status: 403 },
  bad_request_ng: { id: 'bad_request', field: 'request', input: 'uri', status: 403 },
}

export const FIELD_TO_GROUP: Record<FieldName, GroupId> = {
  cookie: 'bad_cookie',
  method: 'not_allowed_method',
  referer: 'bad_referer',
  bot: 'bad_bot',
  querystring: 'bad_querystring',
  request: 'bad_request',
}

export interface Unquoted {
  text: string
  /** map[k] is where character k of text starts in the quoted source; map[text.length] is the source's length. */
  map: number[]
}

// Inside a quoted nginx string, \" \' \\ become the character, \t \r \n a tab, CR or LF; every other backslash stays.
export function nginxUnquoteMapped(s: string): Unquoted {
  let text = ''
  const map: number[] = []
  for (let i = 0; i < s.length; ) {
    map.push(i)
    if (s[i] === '\\' && i + 1 < s.length && `"'\\tnr`.includes(s[i + 1])) {
      const n = s[i + 1]
      text += n === 't' ? '\t' : n === 'n' ? '\n' : n === 'r' ? '\r' : n
      i += 2
    } else {
      text += s[i]
      i += 1
    }
  }
  map.push(s.length)
  return { text, map }
}

export function nginxUnquote(s: string): string {
  return nginxUnquoteMapped(s).text
}

const MAP_OPEN = /^map (\S+) \$(\S+) \{\s*$/
const RULE = /^\s*"~\*(.*)"\s+(\d+);\s*$/
const DEFAULT = /^\s*default\s+(\S+);\s*$/
const SKIP = /^\s*(#.*)?$/

export function compileRule(group: GroupId, number: number, line: number, sourceLine: string, source: string): Rule {
  const pattern = nginxUnquote(source)
  const parsed = parsePcre(pattern)
  return {
    group,
    number,
    line,
    sourceLine,
    source,
    pattern,
    regex: new RegExp(parsed.js, 'i'),
    differences: parsed.differences,
  }
}

/** Parse 8g-firewall.conf into its six groups, in 8g.conf's check order. Throws on any line it does not understand. */
export function parseFirewall(text: string): Map<GroupId, RuleGroup> {
  const found = new Map<GroupId, RuleGroup>()
  let current: RuleGroup | null = null
  let skipping = false
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\r$/, '')
    const n = i + 1
    if (SKIP.test(line)) return
    const open = line.match(MAP_OPEN)
    if (open) {
      if (current || skipping) throw new Error(`line ${n}: a map inside a map`)
      const known = GROUP_BY_VARIABLE[open[2]]
      if (!known) {
        // `map default $ng_reason { default ''; }` only gives $ng_reason an empty default.
        if (open[2] !== 'ng_reason') throw new Error(`line ${n}: unknown map variable $${open[2]}`)
        skipping = true
        return
      }
      if (open[1] !== `$${known.input}`) throw new Error(`line ${n}: $${open[2]} reads ${open[1]}, expected $${known.input}`)
      current = {
        ...known,
        variable: open[2],
        order: CHECK_ORDER.indexOf(known.id),
        line: n,
        rules: [],
      }
      found.set(known.id, current)
      return
    }
    if (/^\s*\}\s*$/.test(line)) {
      if (!current && !skipping) throw new Error(`line ${n}: an unmatched }`)
      current = null
      skipping = false
      return
    }
    const def = line.match(DEFAULT)
    if (def) {
      if (skipping) return
      if (!current) throw new Error(`line ${n}: default outside a map`)
      if (def[1] !== '0') throw new Error(`line ${n}: default is ${def[1]}, expected 0`)
      return
    }
    if (skipping) throw new Error(`line ${n}: unexpected in the $ng_reason map: ${line.slice(0, 60)}`)
    if (!current) throw new Error(`line ${n}: outside a map: ${line.slice(0, 60)}`)
    const rule = line.match(RULE)
    if (!rule) throw new Error(`line ${n}: not a rule: ${line.slice(0, 60)}`)
    const group: RuleGroup = current
    group.rules.push(compileRule(group.id, Number(rule[2]), n, line, rule[1]))
  })
  if (current || skipping) throw new Error('the file ends inside a map')
  const missing = CHECK_ORDER.filter((id) => !found.has(id))
  if (missing.length) throw new Error(`missing maps: ${missing.join(', ')}`)
  return new Map(CHECK_ORDER.map((id) => [id, found.get(id)!]))
}

/** "bot rule 3", for messages. */
export function ruleName(group: GroupId, number: number): string {
  return `${GROUP_BY_VARIABLE[`${group}_ng`].field} rule ${number}`
}
