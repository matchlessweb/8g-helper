// A plain first opinion on a blocked request: leave it blocked, likely a false positive, or the owner's call.
// It is a hint from known request shapes, never proof; the page says so.

import type { LogLine } from './logline.ts'
import type { RuleMatch } from './match.ts'

export type VerdictKind = 'attack' | 'false_positive' | 'judgment'

export interface Verdict {
  kind: VerdictKind
  title: string
  reason: string
}

export const VERDICT_TITLE: Record<VerdictKind, string> = {
  attack: 'Leave it blocked',
  false_positive: 'Likely a false positive',
  judgment: 'Your call',
}

const v = (kind: VerdictKind, reason: string): Verdict => ({ kind, title: VERDICT_TITLE[kind], reason })

// Known plugin and service requests that 7G blocks by mistake.
const KNOWN_FALSE_POSITIVES: { test: (l: LogLine) => boolean; reason: string }[] = [
  {
    test: (l) => /^\/wp-json\/rankmath\/v1\/gethead$/i.test(l.path),
    reason:
      "Rank Math's SEO preview. It sends your own page's address in the query string, and the https:// in it looks like a remote file include to 7G.",
  },
  {
    test: (l) => /(^|&)redirect_uri=https?(:|%3a)(\/|%2f){2}(localhost|127\.0\.0\.1)/i.test(l.queryString),
    reason:
      'An OAuth sign-in redirect to a local app (an MCP client or a desktop tool). 7G blocks localhost in a query string, which breaks the sign-in.',
  },
]

const ATTACK_PATHS =
  /(^|\/)\.(env|git|svn|hg|aws|ssh|htpasswd|ds_store)(\/|$|\.)|wp-config|(^|\/)(config|sql|shell|phpinfo|info|adminer|eval-stdin)\.php|(web\.config|docker-compose[\w.-]*|\.ya?ml|\.sql|\.bak|\.old|\.swp|\.log)$|\/(cgi-bin|tmp|database|htdocs|httpdocs|var\/www|vendor\/phpunit)\/|etc\/passwd|self\/environ|union.{0,20}select|base64_decode|(<|%3c)script/i

const SCANNER_AGENTS =
  /go-http-client|python-requests|python-urllib|aiohttp|curl\/|wget\/|zgrab|masscan|sqlmap|nikto|nuclei|libwww-perl|okhttp/i

interface KnownBot {
  ua: RegExp
  name: string
  kind: VerdictKind
  reason: string
}

const preview = (name: string): string =>
  `${name}'s link preview fetcher. While it is blocked, links to this site shared there show no title or image.`
const search = (name: string): string =>
  `${name}'s search crawler. Blocking it keeps your pages out of its results. A user agent can be faked, so check the IP belongs to ${name} before you allow it.`
const ai = (owner: string): string =>
  `An AI crawler run by ${owner}. Allowing it lets ${owner} read your pages for its models or answers; blocking it keeps them out.`
const seo = (name: string): string =>
  `An SEO tool's crawler. Allow it if you use ${name} on this site; if you don't, it costs server time and gives you nothing.`

const KNOWN_BOTS: KnownBot[] = [
  { ua: /facebookexternalhit|facebookcatalog/i, name: 'Facebook', kind: 'false_positive', reason: preview('Facebook') },
  { ua: /twitterbot/i, name: 'X (Twitter)', kind: 'false_positive', reason: preview('X') },
  { ua: /linkedinbot/i, name: 'LinkedIn', kind: 'false_positive', reason: preview('LinkedIn') },
  { ua: /slackbot/i, name: 'Slack', kind: 'false_positive', reason: preview('Slack') },
  { ua: /discordbot/i, name: 'Discord', kind: 'false_positive', reason: preview('Discord') },
  { ua: /whatsapp/i, name: 'WhatsApp', kind: 'false_positive', reason: preview('WhatsApp') },
  { ua: /telegrambot/i, name: 'Telegram', kind: 'false_positive', reason: preview('Telegram') },
  { ua: /pinterestbot/i, name: 'Pinterest', kind: 'false_positive', reason: preview('Pinterest') },
  { ua: /gptbot|chatgpt-user|oai-searchbot/i, name: 'OpenAI', kind: 'judgment', reason: ai('OpenAI') },
  { ua: /claudebot|claude-user|claude-searchbot|anthropic-ai/i, name: 'Anthropic', kind: 'judgment', reason: ai('Anthropic') },
  { ua: /perplexitybot|perplexity-user/i, name: 'Perplexity', kind: 'judgment', reason: ai('Perplexity') },
  { ua: /ccbot/i, name: 'Common Crawl', kind: 'judgment', reason: ai('Common Crawl') },
  { ua: /bytespider/i, name: 'ByteDance', kind: 'judgment', reason: ai('ByteDance') },
  { ua: /meta-externalagent/i, name: 'Meta', kind: 'judgment', reason: ai('Meta') },
  { ua: /amazonbot/i, name: 'Amazon', kind: 'judgment', reason: ai('Amazon') },
  { ua: /applebot-extended/i, name: 'Apple', kind: 'judgment', reason: ai('Apple') },
  { ua: /googlebot/i, name: 'Google', kind: 'false_positive', reason: search('Google') },
  { ua: /bingbot/i, name: 'Bing', kind: 'false_positive', reason: search('Bing') },
  { ua: /applebot/i, name: 'Apple', kind: 'false_positive', reason: search('Apple') },
  { ua: /duckduckbot/i, name: 'DuckDuckGo', kind: 'false_positive', reason: search('DuckDuckGo') },
  {
    ua: /petalbot/i,
    name: 'PetalBot',
    kind: 'judgment',
    reason:
      "Huawei's search crawler (Petal Search). 7G blocks it out of the box, and it brings little traffic to most US sites. Allow it only if you want to appear in Petal Search.",
  },
  { ua: /ahrefs/i, name: 'Ahrefs', kind: 'judgment', reason: seo('Ahrefs') },
  { ua: /semrush/i, name: 'Semrush', kind: 'judgment', reason: seo('Semrush') },
  { ua: /mj12bot|majestic/i, name: 'Majestic', kind: 'judgment', reason: seo('Majestic') },
  { ua: /rogerbot|dotbot/i, name: 'Moz', kind: 'judgment', reason: seo('Moz') },
  { ua: /blexbot/i, name: 'BLEXBot', kind: 'judgment', reason: seo('WebMeUp (BLEXBot)') },
]

export function knownBot(userAgent: string): KnownBot | undefined {
  return KNOWN_BOTS.find((b) => b.ua.test(userAgent))
}

export function judge(line: LogLine, matches: RuleMatch[]): Verdict {
  const fp = KNOWN_FALSE_POSITIVES.find((k) => k.test(line))
  if (fp) return v('false_positive', fp.reason)

  if (ATTACK_PATHS.test(line.uri)) {
    return v(
      'attack',
      'This asks for a file no visitor needs: a secrets file, a config file, a backup or a web shell. Scanners try these on every site. 7G is doing its job.',
    )
  }

  if (matches.some((m) => m.hit.group === 'bad_bot')) {
    const bot = knownBot(line.userAgent)
    if (bot) return v(bot.kind, bot.reason)
  }

  if (/["]|%22/i.test(line.uri)) {
    return v(
      'attack',
      'No real page address holds a quote mark. This is a scraper following a broken link it pulled out of a page’s source. Nothing a visitor needs is blocked.',
    )
  }

  if (SCANNER_AGENTS.test(line.userAgent)) {
    return v(
      'attack',
      'The user agent is a script library, not a browser, and the request matches an attack pattern. If you sent it yourself while testing, this is your call; otherwise leave it.',
    )
  }

  if (matches.some((m) => m.hit.group === 'bad_bot')) {
    return v(
      'judgment',
      'A crawler 7G does not like. If you know it and want it on your site, allow it; if you have never heard of it, leave it blocked.',
    )
  }

  return v(
    'judgment',
    `Nothing here says attack or false positive for sure. If ${line.path || 'this address'} is a page, form or plugin on your site that people use, it is likely a false positive. If not, leave it blocked.`,
  )
}
