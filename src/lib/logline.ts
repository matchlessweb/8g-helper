// One line of a GridPane 7G log (/var/www/<site>/logs/7g.log), as GridPane's 7g_log format writes it:
// [time] [":<group>_<n>:..."] ip host "METHOD URI PROTOCOL" status time "referer" "user agent"
// nginx writes a quote or backslash inside a field as \x22 or \x5C, so no field holds a raw quote.

import type { GroupId } from './rules.ts'

export interface Hit {
  group: GroupId
  number: number
}

export interface LogLine {
  raw: string
  time: string
  hits: Hit[]
  ip: string
  host: string
  method: string
  /** The request URI exactly as nginx saw it ($request_uri): still percent-encoded, with its query string. */
  uri: string
  path: string
  queryString: string
  protocol: string
  status: string
  referer: string
  userAgent: string
}

export type ParseResult = { ok: true; line: LogLine } | { ok: false; raw: string; reason: string }

// The fields after the request are optional: GridPane's own docs, and some copies, stop after the status.
const LINE = /^\[([^\]]+)\] \["([^"]*)"\] (\S+) (\S+) "([^"]*)"(?: (\d{3}))?(?: (\S+))?(?: "([^"]*)")?(?: "([^"]*)")?\s*$/
const HIT = /:([a-z_]+)_(\d+):/g
const GROUPS: readonly GroupId[] = ['bad_bot', 'bad_referer', 'bad_querystring', 'bad_request', 'not_allowed_method']

/** nginx's log escaping: \xHH back to the character. */
export function unescapeLog(s: string): string {
  return s.replace(/\\x([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
}

export function parseLogLine(input: string): ParseResult {
  const raw = input.trim()
  const m = raw.match(LINE)
  if (!m) {
    const reason = raw.includes('bad_') && raw.startsWith('[')
      ? 'It looks like a 7G line, but part of it is missing. Copy the whole line, from the opening [ to the closing quote.'
      : 'This is not a 7G log line. Lines from /var/www/<site>/logs/7g.log start with the time in [brackets], then the rule.'
    return { ok: false, raw, reason }
  }
  const [, time, reasons, ip, host, request, status, , referer, userAgent] = m
  const hits: Hit[] = []
  for (const h of reasons.matchAll(HIT)) {
    const group = h[1] as GroupId
    if (GROUPS.includes(group)) hits.push({ group, number: Number(h[2]) })
  }
  if (hits.length === 0) {
    return { ok: false, raw, reason: `The line names no 7G rule (it says "${reasons}"), so 7G did not block it.` }
  }
  const req = unescapeLog(request)
  const parts = req.split(' ')
  const protocol = parts.length > 2 && /^HTTP\//.test(parts[parts.length - 1]) ? parts.pop()! : ''
  const method = parts.length > 1 ? parts.shift()! : ''
  const uri = parts.join(' ')
  const q = uri.indexOf('?')
  return {
    ok: true,
    line: {
      raw,
      time,
      hits,
      ip,
      host,
      method,
      uri,
      path: q === -1 ? uri : uri.slice(0, q),
      queryString: q === -1 ? '' : uri.slice(q + 1),
      protocol,
      status: status ?? '',
      referer: !referer || referer === '-' ? '' : unescapeLog(referer),
      userAgent: !userAgent || userAgent === '-' ? '' : unescapeLog(userAgent),
    },
  }
}

/** Split pasted text into log lines, skipping blanks and # comments. */
export function splitLines(text: string): string[] {
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
}
