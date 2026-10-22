// The exception file, in the strict form: it lets one request shape through only when the rule that fired is the
// one in the log. Every other 7G rule stays on for that request, and that rule stays on for every other request.
// GridPane includes these files after the maps set the drop flags and before it drops the request, and keeps them
// through its updates: per site /var/www/<site>/nginx/*-7g-context.conf, server-wide /etc/nginx/extra.d/*7g-context.conf.

import type { LogLine } from './logline.ts'
import type { RuleMatch } from './match.ts'
import { knownBot } from './verdict.ts'

export type Scope = 'site' | 'server'

export interface ExceptionFile {
  fileName: string
  path: string
  content: string
  reload: string
  /** Should come back with anything but 403 once the file is in place. */
  testAllowed: string
  /** Should still come back 403: proof the rest of 7G is on. */
  testStillBlocked: string
}

const RELOAD = 'nginx -t && gp ngx reload'

/** The GridPane site folder: the logged host without a leading www. */
export function siteFolder(host: string): string {
  return host.toLowerCase().replace(/^www\./, '')
}

function slugify(s: string, max = 40): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max).replace(/-+$/, '') || 'request'
}

// A literal string as an nginx regex inside double quotes. nginx unescapes \\ and \" in a quoted string before the
// regex sees it, so a literal backslash needs four, and a quote needs one; \. and the like pass through untouched.
export function nginxRegex(literal: string): string {
  return literal
    .replace(/\\/g, '\\\\\\\\')
    .replace(/[.*+?^${}()|[\]]/g, '\\$&')
    .replace(/"/g, '\\"')
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

/** The crawler's own name from a user agent, e.g. GPTBot or facebookexternalhit. */
export function botToken(userAgent: string): string {
  const named = userAgent.match(/\b([a-z][\w.-]*?(?:bot|crawler|spider|externalhit|fetcher|agent))\b/i)
  if (named && !/^mozilla$/i.test(named[1])) return named[1]
  const product = userAgent.match(/\b([a-z][\w.-]{2,})\//gi)?.map((p) => p.slice(0, -1)).find((p) => !/^(mozilla|applewebkit|chrome|safari|gecko|version|mobile)$/i.test(p))
  return product ?? userAgent.slice(0, 40)
}

interface Condition {
  /** The nginx test, e.g. $http_user_agent ~* "GPTBot". */
  test: string
  /** Plain words for the file's header. */
  says: string
  slug: string
}

function condition(m: RuleMatch, line: LogLine): Condition {
  // Without the user agent or referrer in the line, the only safe scope left is the address.
  const group = (m.hit.group === 'bad_bot' && !line.userAgent) || (m.hit.group === 'bad_referer' && !line.referer) ? 'path' : m.hit.group
  switch (group) {
    case 'bad_bot': {
      const text = m.matched?.text
      const token = text && /^[\w .-]{3,40}$/.test(text) ? text : botToken(line.userAgent)
      return {
        test: `$http_user_agent ~* "${nginxRegex(token)}"`,
        says: `a user agent containing "${token}"`,
        slug: slugify(knownBot(line.userAgent)?.name ?? token, 24),
      }
    }
    case 'bad_referer': {
      const host = line.referer.match(/^https?:\/\/([^/?#]+)/i)?.[1] ?? line.referer
      return {
        test: `$http_referer ~* "^https?://${nginxRegex(host)}(/|$)"`,
        says: `links from ${host}`,
        slug: slugify(host, 24),
      }
    }
    default: {
      const path = line.path || '/'
      return {
        test: `$request_uri ~ "^${nginxRegex(path)}(\\?|$)"`,
        says: `requests to ${path}`,
        slug: slugify(path.split('/').filter(Boolean).slice(-3).join('-'), 32),
      }
    }
  }
}

export function buildException(line: LogLine, matches: RuleMatch[], scope: Scope, today: string): ExceptionFile {
  const conds = matches.map((m) => ({ m, c: condition(m, line) }))
  const slug = [...new Set(conds.map(({ c }) => c.slug))].join('-').slice(0, 48).replace(/-+$/, '')
  const fileName = `allow-${slug}-7g-context.conf`
  const site = siteFolder(line.host)
  const path = scope === 'site' ? `/var/www/${site}/nginx/${fileName}` : `/etc/nginx/extra.d/${fileName}`

  const header = [
    `# 7G exception, written by 7G Helper on ${today} from this 7G log line:`,
    `#   ${line.raw}`,
    '#',
    ...conds.map(
      ({ m, c }) => `# Lets through ${c.says}, only when ${m.hit.group} rule ${m.hit.number} is what blocked it.`,
    ),
    `# Every other 7G rule stays on for ${conds.length > 1 ? 'these requests' : 'this request'}, and ${conds.length > 1 ? 'these rules stay' : 'this rule stays'} on for everything else.`,
    scope === 'site'
      ? `# Applies to ${site} only.`
      : '# Applies to every 7G-enabled site on this server.',
    '# 7G Helper is independent of GridPane and of 7G. Review this file before you use it.',
    '#',
    `# Save as: ${path}`,
    `# Then run: ${RELOAD}`,
  ]

  const blocks = conds.map(({ m, c }) => {
    const variable = `$allow7g_${c.slug.replace(/-/g, '_')}_${m.hit.group}_${m.hit.number}`
    return [
      `set ${variable} "";`,
      `if (${c.test}) {`,
      `    set ${variable} ${m.hit.number};`,
      '}',
      `if ($${m.group.variable} = ${variable}) {`,
      `    set $${m.group.dropFlag} 0;`,
      '}',
    ].join('\n')
  })

  const url = `https://${line.host}${line.uri || '/'}`
  const method = line.method && line.method !== 'GET' ? ` -X ${line.method}` : ''
  const isBot = matches.some((m) => m.hit.group === 'bad_bot') && line.userAgent !== ''
  const ua = isBot ? ` -A ${shellQuote(line.userAgent)}` : ''
  const code = `curl -s -o /dev/null -w '%{http_code}\\n'`
  const control = isBot
    ? `${code} -A ${/blexbot/i.test(line.userAgent) ? "'MJ12bot'" : "'BLEXBot'"} ${shellQuote(`https://${line.host}/`)}`
    : `${code} ${shellQuote(`https://${line.host}/.env`)}`

  return {
    fileName,
    path,
    content: `${header.join('\n')}\n\n${blocks.join('\n\n')}\n`,
    reload: RELOAD,
    testAllowed: `${code}${method}${ua} ${shellQuote(url)}`,
    testStillBlocked: control,
  }
}
