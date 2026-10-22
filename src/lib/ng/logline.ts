// One pasted line, in any of the three shapes the 8G Helper reads:
//
// 'ng8'       Our 8G log (/var/www/<site>/logs/8g.log), watch and enforce mode alike, from this log_format:
//             $time_iso8601 $status "$request_method $request_uri" cookie=$bad_cookie_ng method=$not_allowed_method_ng
//             referer=$bad_referer_ng bot=$bad_bot_ng querystring=$bad_querystring_ng request=$bad_request_ng
//             ip=$remote_addr ua="$http_user_agent" ref="$http_referer"
//             Older lines have ip= empty or a Cloudflare header value; an empty number (cookie=) reads as 0.
// 'ng_reason' Any line carrying nG's $ng_reason tokens, e.g. :bad_querystring_2: or :not_allowed_method_1:.
// 'combined'  An access log line in the nginx or Apache default: IP - - [time] "GET /x?q HTTP/1.1" 200 5 "ref" "ua".
//
// nginx's log escaping (escape=default) writes ", \ and every byte outside 0x20-0x7e as \xHH, and an empty variable
// as -. Apache writes " and \ as \" and \\. Both are undone here, into a byte string: one character per byte, as
// nginx matched it. Text pasted with real non-ASCII characters is encoded to UTF-8 bytes first.

import { CHECK_ORDER, type GroupId } from './rules.ts'
import { normalizeUri, splitRequestUri, type UriProblem } from './uri.ts'

export type LineFormat = 'ng8' | 'ng_reason' | 'combined'

export interface LogLine {
  raw: string
  format: LineFormat
  /** As the line writes it ('' when the line has none). */
  time: string
  /** The response status as logged, e.g. '403' ('' when the line has none). */
  status: string
  ip: string
  /** undefined when the line does not carry the request at all. */
  method?: string
  /** $request_uri: the raw path and query string, as the client sent it. */
  requestUri?: string
  /** The raw path, before the first ?. */
  path?: string
  /** $query_string: raw, after the first ? ('' when there is none). */
  queryString?: string
  /** $uri: the decoded, normalized path 8G's request rules read. undefined when it cannot be built (see uriProblem). */
  uri?: string
  /** Why $uri could not be built: nginx would answer 400 before 8G ran, or the request is missing. */
  uriProblem?: { problem: UriProblem; reason: string }
  protocol: string
  /** '' when the header was absent (logged as -); undefined when the line does not carry it. */
  userAgent?: string
  referer?: string
  /** What the line says each group returned. ng8: all six; ng_reason: the named groups; combined: none. */
  logged: Partial<Record<GroupId, number>>
  /** Parts of the line were shortened before it was pasted (abcd... or …), so some text is not what nginx saw. */
  cut: boolean
}

export type ParseResult = { ok: true; line: LogLine } | { ok: false; raw: string; reason: string }

/** nginx's \xHH and Apache's \" and \\ back to the byte. */
export function unescapeLog(s: string): string {
  return s.replace(/\\x([0-9A-Fa-f]{2})|\\(["\\])/g, (_, h: string | undefined, c: string | undefined) =>
    h !== undefined ? String.fromCharCode(parseInt(h, 16)) : c!,
  )
}

/** Characters above 0x7f become their UTF-8 bytes, one character per byte. ASCII is unchanged. */
export function toBytes(s: string): string {
  if (!/[^\x00-\x7f]/.test(s)) return s
  return Array.from(new TextEncoder().encode(s), (b) => String.fromCharCode(b)).join('')
}

/** A byte string made readable: bytes outside 0x20-0x7e as \xHH, the way nginx logs them. Use it to show values. */
export function printable(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`)
}

/** Split pasted text into lines, skipping blanks and # comments. */
export function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
}

/** Spans of text a report or a person shortened: four letters or digits then ... (as our report masks keys), or …. */
export function cutSpans(s: string): { start: number; end: number }[] {
  const spans: { start: number; end: number }[] = []
  for (const m of s.matchAll(/(?<![A-Za-z0-9])[A-Za-z0-9]{4}(\.\.\.)|\xE2\x80\xA6/g)) {
    const start = m[1] ? m.index + 4 : m.index
    spans.push({ start, end: m.index + m[0].length })
  }
  return spans
}

const FIELD_GROUP: Record<string, GroupId> = {
  cookie: 'bad_cookie',
  method: 'not_allowed_method',
  referer: 'bad_referer',
  bot: 'bad_bot',
  querystring: 'bad_querystring',
  request: 'bad_request',
}

const SEVEN_G = /^\[[^\]]+\] \["[^"]*"\] \S+ \S+ "/
const NG8_HEAD = /^(\d{4}-\d\d-\d\dT\S+) (\d{3}) "([^"]*)"(.*)$/
const NG8_FIELD = /(?:^| )(cookie|method|referer|bot|querystring|request)=(\d*)(?= |$)/g
const QUOTED = '"((?:[^"\\\\]|\\\\.)*)"'
const COMBINED = new RegExp(
  `^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] ${QUOTED} (\\d{3}) (\\S+)(?: ${QUOTED})?(?: ${QUOTED})?(.*)$`,
)
const TOKEN = /:(bad_cookie|not_allowed_method|bad_referer|bad_bot|bad_querystring|bad_request)_(\d+):/g
const TOKENS_ONLY = /^(?::[a-z_]+_\d+:)+$/
// nginx splits the request line on spaces only. (JavaScript's \S would also stop at a 0xA0 byte.)
const REQUEST = /^([A-Za-z_-]+) ([^ ]+)(?: (HTTP\/[\d.]+))?$/

const fromLog = (s: string | undefined): string | undefined =>
  s === undefined ? undefined : s === '-' ? '' : unescapeLog(s)

interface Request {
  method: string
  requestUri: string
  protocol: string
}

function parseRequest(text: string): Request | undefined {
  const m = text.match(REQUEST)
  return m ? { method: m[1], requestUri: m[2], protocol: m[3] ?? '' } : undefined
}

/** $ng_reason tokens outside quoted fields, or inside a quoted field that holds nothing else ("$ng_reason"). */
function reasonTokens(raw: string): { group: GroupId; number: number }[] {
  const outside = raw.replace(/"((?:[^"\\]|\\.)*)"/g, (all, inner: string) => (TOKENS_ONLY.test(inner) ? all : '""'))
  return [...outside.matchAll(TOKEN)].map((t) => ({ group: t[1] as GroupId, number: Number(t[2]) }))
}

function build(
  raw: string,
  format: LineFormat,
  parts: {
    time: string
    status: string
    ip: string
    request?: Request
    userAgent?: string
    referer?: string
    logged: Partial<Record<GroupId, number>>
  },
): LogLine {
  const line: LogLine = {
    raw,
    format,
    time: parts.time,
    status: parts.status,
    ip: parts.ip,
    protocol: parts.request?.protocol ?? '',
    userAgent: parts.userAgent,
    referer: parts.referer,
    logged: parts.logged,
    cut: false,
  }
  const req = parts.request
  if (req) {
    line.method = req.method
    line.requestUri = req.requestUri
    const target = splitRequestUri(req.requestUri)
    line.path = target.path
    line.queryString = target.queryString
    const uri = normalizeUri(target.path)
    if (uri.ok) line.uri = uri.uri
    else line.uriProblem = { problem: uri.problem, reason: uri.reason }
  }
  line.cut = [line.requestUri, line.userAgent, line.referer].some((v) => v !== undefined && cutSpans(v).length > 0)
  return line
}

export function parseLogLine(input: string): ParseResult {
  const raw = input.trim()
  const text = toBytes(raw)

  if (SEVEN_G.test(text)) {
    return {
      ok: false,
      raw,
      reason:
        'This is a 7G log line (from /var/www/<site>/logs/7g.log), not an 8G one. 7G Helper reads those; this tool reads the 8G log.',
    }
  }

  const head = text.match(NG8_HEAD)
  if (head) {
    const [, time, status, request, rest] = head
    const logged: Partial<Record<GroupId, number>> = {}
    for (const f of rest.matchAll(NG8_FIELD)) logged[FIELD_GROUP[f[1]]] = f[2] === '' ? 0 : Number(f[2])
    if (CHECK_ORDER.some((g) => logged[g] === undefined)) {
      return {
        ok: false,
        raw,
        reason:
          'It looks like an 8G log line, but part of it is missing. Copy the whole line, from the time at the start to ref="…" at the end.',
      }
    }
    const req = parseRequest(unescapeLog(request))
    if (!req) {
      return { ok: false, raw, reason: `The request in this line ("${request.slice(0, 40)}") is not an HTTP request, so 8G had nothing to check.` }
    }
    return {
      ok: true,
      line: build(raw, 'ng8', {
        time,
        status,
        ip: rest.match(/ ip=(\S*)/)?.[1] ?? '',
        request: req,
        userAgent: fromLog(rest.match(/ ua="([^"]*)"/)?.[1]),
        referer: fromLog(rest.match(/ ref="([^"]*)"/)?.[1]),
        logged,
      }),
    }
  }

  const tokens = reasonTokens(text)
  const logged: Partial<Record<GroupId, number>> = {}
  for (const t of tokens) if (logged[t.group] === undefined) logged[t.group] = t.number
  const combined = text.match(COMBINED)

  if (combined) {
    const [, ip, , , time, request, status, , referer, userAgent] = combined
    const req = request === '-' ? undefined : parseRequest(unescapeLog(request))
    if (!req) {
      return {
        ok: false,
        raw,
        reason: `The request in this line is ${request === '-' ? 'empty (-)' : 'not an HTTP request'}, so 8G had nothing to check.`,
      }
    }
    return {
      ok: true,
      line: build(raw, tokens.length ? 'ng_reason' : 'combined', {
        time,
        status,
        ip,
        request: req,
        userAgent: fromLog(userAgent),
        referer: fromLog(referer),
        logged,
      }),
    }
  }

  if (tokens.length) {
    // A format of the reader's own: use whatever request the line has. The user agent and referrer are not known.
    let request: Request | undefined
    for (const q of text.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
      const r = parseRequest(unescapeLog(q[1]))
      if (r && r.requestUri.startsWith('/')) {
        request = r
        break
      }
    }
    if (!request) {
      const m = text.match(/(?:^| )([A-Z]{3,10}) (\/[^ ]*)(?: (HTTP\/[\d.]+))?(?= |$)/)
      if (m) request = { method: m[1], requestUri: unescapeLog(m[2]), protocol: m[3] ?? '' }
    }
    return {
      ok: true,
      line: build(raw, 'ng_reason', {
        time: text.match(/\[([^\]]+)\]/)?.[1] ?? text.match(/\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?/)?.[0] ?? '',
        status: text.match(/" (\d{3})(?= |$)/)?.[1] ?? '',
        ip: '',
        request,
        logged,
      }),
    }
  }

  const reason = /(?:^|\s)(?:cookie|bot|querystring|request)=\d*(?:\s|$)/.test(text)
    ? 'It looks like an 8G log line, but its start is missing. Copy the whole line, from the time at the start to ref="…" at the end.'
    : 'This is not a line the 8G Helper can read. Paste a line from the 8G log (/var/www/<site>/logs/8g.log), a line that includes $ng_reason, or a line from the site’s access log.'
  return { ok: false, raw, reason }
}
