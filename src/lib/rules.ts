// GridPane's 7G maps, read from the shipped file (rules/gridpane-7g-mappings.conf, Version 1.4, copied from
// /etc/nginx/common/7g-mappings.conf on a GridPane server on 2026-10-21). The file is parsed as nginx reads it.

export type GroupId = 'bad_bot' | 'bad_referer' | 'bad_querystring' | 'bad_request' | 'not_allowed_method'

export type InputName = 'http_user_agent' | 'http_referer' | 'query_string' | 'request_uri' | 'request_method'

export interface Rule {
  number: number
  /** The pattern as written in the file, inside its quotes. */
  source: string
  /** The pattern after nginx's own unescaping, compiled case-insensitive (nginx `~*`). */
  regex: RegExp
}

export interface RuleGroup {
  id: GroupId
  /** The map's output variable, e.g. bad_request_7g. */
  variable: string
  /** The nginx variable the map reads, e.g. request_uri. */
  input: InputName
  /** The flag an exception resets to 0, e.g. 7g_drop_bad_request. */
  dropFlag: string
  /** The extra.d file pattern GridPane includes at the top of this map, for custom entries. */
  customInclude: string
  rules: Rule[]
}

export const RULESET_SOURCE = {
  name: 'GridPane 7G Firewall mappings',
  version: '1.4',
  path: '/etc/nginx/common/7g-mappings.conf',
  copied: '2026-10-21',
}

const GROUP_BY_VARIABLE: Record<string, { id: GroupId; dropFlag: string }> = {
  bad_bot_7g: { id: 'bad_bot', dropFlag: '7g_drop_bad_bot' },
  bad_referer_7g: { id: 'bad_referer', dropFlag: '7g_drop_bad_referer' },
  bad_querystring_7g: { id: 'bad_querystring', dropFlag: '7g_drop_bad_query_string' },
  bad_request_7g: { id: 'bad_request', dropFlag: '7g_drop_bad_request' },
  not_allowed_method_7g: { id: 'not_allowed_method', dropFlag: '7g_drop_bad_method' },
}

// Inside a quoted nginx string, \" \' \\ \t \r \n are unescaped; every other backslash stays as written.
export function nginxUnquote(s: string): string {
  return s.replace(/\\(["'\\tnr])/g, (_, c: string) => ({ t: '\t', n: '\n', r: '\r' })[c] ?? c)
}

const MAP_OPEN = /^map \$(\S+) \$(\S+) \{\s*$/
const RULE = /^\s*(?:"~\*(.*)"|~\*(\S+))\s+(\d+);\s*$/
const INCLUDE = /^\s*include\s+(\S+);\s*$/
const IGNORED = /^\s*(#.*|default\s+\S+;|\}|)\s*$/

/** Parse the mappings file. Throws on any line it does not understand, so a changed file is never half-read. */
export function parseMappings(text: string): Map<GroupId, RuleGroup> {
  const groups = new Map<GroupId, RuleGroup>()
  let current: RuleGroup | null = null
  text.split('\n').forEach((line, i) => {
    const open = line.match(MAP_OPEN)
    if (open) {
      const known = GROUP_BY_VARIABLE[open[2]]
      if (!known) throw new Error(`line ${i + 1}: unknown map variable $${open[2]}`)
      current = {
        id: known.id,
        variable: open[2],
        input: open[1] as InputName,
        dropFlag: known.dropFlag,
        customInclude: '',
        rules: [],
      }
      groups.set(known.id, current)
      return
    }
    if (IGNORED.test(line)) {
      if (/^\s*\}\s*$/.test(line)) current = null
      return
    }
    if (!current) throw new Error(`line ${i + 1}: outside a map: ${line.slice(0, 60)}`)
    const group: RuleGroup = current
    const include = line.match(INCLUDE)
    if (include) {
      group.customInclude = include[1]
      return
    }
    const rule = line.match(RULE)
    if (!rule) throw new Error(`line ${i + 1}: not a rule: ${line.slice(0, 60)}`)
    const source = rule[1] ?? rule[2]
    const pattern = rule[1] !== undefined ? nginxUnquote(rule[1]) : rule[2]
    group.rules.push({ number: Number(rule[3]), source, regex: new RegExp(pattern, 'i') })
  })
  return groups
}
