// A plain first opinion on what 8G blocked (or, in watch mode, would block): leave it blocked, likely a false positive,
// a crawler to decide on, or the owner's call. It is a hint from known request shapes, never proof; the page says so.
// 8G's user agent rules are a crawler policy (names 8G would rather not serve), not attack signatures, so a known
// crawler gets its own kind instead of "leave it blocked".

import type { LogLine } from './logline.ts'
import type { GroupResult } from './match.ts'
import type { GroupId } from './rules.ts'

export type VerdictKind = 'attack' | 'false_positive' | 'crawler' | 'judgment'

export interface Verdict {
  kind: VerdictKind
  title: string
  reason: string
  /** The crawler or tool, when the user agent names one 8G Helper knows. */
  crawler?: string
}

export const VERDICT_TITLE: Record<VerdictKind, string> = {
  attack: 'Leave it blocked',
  false_positive: 'Likely a false positive',
  crawler: 'Crawler policy',
  judgment: 'Your call',
}

const v = (kind: VerdictKind, reason: string, crawler?: string): Verdict => ({
  kind,
  title: VERDICT_TITLE[kind],
  reason,
  ...(crawler ? { crawler } : {}),
})

/** Every rule number that matched (or was logged) in one group. */
function hitNumbers(groups: GroupResult[], id: GroupId): number[] {
  const g = groups.find((x) => x.group.id === id)
  if (!g) return []
  const n = g.matches.map((m) => m.rule.number)
  if (g.logged) n.push(g.logged)
  return n
}

const hits = (groups: GroupResult[], id: GroupId, numbers: number[]): boolean =>
  hitNumbers(groups, id).some((n) => numbers.includes(n))

// Words in a site search that look like SQL to 8G: rules 27-30 (+delete+ +insert+ +select+ +update+), 39 (+get+ and
// friends), and the loose function-call rules 19, 21, 40 and 41 (html…( eval…( union…select concat…().
const SEARCH_RULES = [19, 21, 27, 28, 29, 30, 39, 40, 41]
const SQL_SIGNS =
  /'|%27|--|\/\*|%2f\*|0x[0-9a-f]{2}|\bunion(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select\b|\b(?:sleep|benchmark|concat|char|load_file|extractvalue|updatexml)(?:\s|\+|%20)*(?:\(|%28)/i

const KNOWN_FALSE_POSITIVES: { test: (l: LogLine, g: GroupResult[]) => boolean; reason: string }[] = [
  {
    test: (l, g) =>
      /(?:^|&)s=/i.test(l.queryString ?? '') && hits(g, 'bad_querystring', SEARCH_RULES) && !SQL_SIGNS.test(l.queryString ?? ''),
    reason:
      'A visitor’s site search. 8G blocks searches that put words such as get, select, update, delete or union between other words, because SQL injection uses them too (nG-SetEnvIf issue #20). Real searches hit it.',
  },
  {
    test: (l, g) =>
      hits(g, 'bad_querystring', [9]) && /(?:^|&)redirect_uri=https?(?::|%3a)(?:\/|%2f){2}(?:localhost|127\.0\.0\.1)/i.test(l.queryString ?? ''),
    reason:
      'An OAuth sign-in redirect to a local app (an MCP client or a desktop tool). 8G blocks localhost in a query string, which breaks the sign-in.',
  },
]

const ATTACK_PATHS =
  /(^|\/)\.(env|git|svn|hg|aws|ssh|htpasswd|htaccess|ds_store)(\/|$|\.)|wp-config|(^|\/)(config|sql|shell|phpinfo|info|adminer|eval-stdin)\.php|(web\.config|docker-compose[\w.-]*|\.ya?ml|\.sql|\.bak|\.old|\.swp|\.log|\.env|\.ini|\.sh)$|\/(cgi-bin|tmp|database|htdocs|httpdocs|var\/www|vendor\/phpunit)\/|etc\/passwd|self\/environ|union.{0,20}select|base64_decode|(<|%3c)script/i

// Request rules that only ever fire on probes: web shells, backdoors, config and backup files, scanner paths.
const PROBE_REQUEST_RULES = [
  6, 8, 9, 10, 15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 33, 34, 35, 36, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 50,
  51, 52, 53, 54,
]
// Request rules that fire on code or broken text in the address: injection attempts and scrapers' broken links.
const INJECTION_REQUEST_RULES = [1, 3, 4, 5, 7, 11, 13, 14, 23, 29, 32, 37, 38]
// Query string rules that only fire on attack text: traversal, file includes, PHP functions, SQL.
const ATTACK_QUERY_RULES = [1, 2, 3, 4, 5, 7, 8, 10, 12, 13, 14, 15, 16, 17, 18, 20, 22, 23, 24, 25, 26, 31, 32, 33, 34, 35, 36, 37, 38]
// User agent rules that are attack text, not names: one character, encoded injection, web shells, shell commands.
const ATTACK_BOT_RULES = [1, 2, 4, 5]

const SCANNER_TOOLS = /mozlila|nikto|masscan|sqlmap|zmeu|morfeus|nessus|nmap|zgrab|nuclei|wpscan|acunetix|netsparker/i

export interface KnownCrawler {
  ua: RegExp
  name: string
  reason: string
}

const ai = (owner: string): string =>
  `An AI crawler run by ${owner}. 8G blocks it by name: a choice about crawlers, not an attack. Allow it if you want ${owner} to read your pages for its models or answers; leave it blocked if not. robots.txt is the gentler way to say no.`
const search = (name: string, what: string): string =>
  `${name}’s search crawler (${what}). Blocking it keeps your pages out of ${name}’s results; allow it if you want visitors from there. A user agent can be faked, so check the IP belongs to ${name} first.`
const seo = (name: string): string =>
  `An SEO tool’s crawler. Allow it if you use ${name} on this site; if you don’t, it costs server time and gives you nothing.`
const seoData = (name: string): string =>
  `${name} crawls the web to sell link and ranking data to SEO tools. It brings you no visitors. Leave it blocked unless a tool you use is built on ${name}.`

const KNOWN_CRAWLERS: KnownCrawler[] = [
  {
    ua: /merchantsecurityscanner/i,
    name: 'Stripe',
    reason:
      'Stripe’s security scanner, which checks sites that take payments through Stripe. 8G blocks it only because its name contains “scan”. If this site takes payments with Stripe, you likely want it allowed.',
  },
  {
    ua: /ahrefs/i,
    name: 'Ahrefs',
    reason:
      'Ahrefs’ SEO crawler (AhrefsBot, and AhrefsSiteAudit for its Site Audit). Allow it if you use Ahrefs on this site; Jeff Starr’s advice is to delete ahrefs| from bot rule 3. If you don’t use Ahrefs, it costs server time and gives you nothing.',
  },
  { ua: /claudebot/i, name: 'Anthropic', reason: ai('Anthropic') },
  { ua: /bytespider/i, name: 'ByteDance', reason: ai('ByteDance') },
  { ua: /ccbot|commoncrawl/i, name: 'Common Crawl', reason: ai('Common Crawl, a nonprofit web archive that AI companies train on,') },
  { ua: /seznambot/i, name: 'Seznam', reason: search('Seznam', 'the main search engine in the Czech Republic') },
  { ua: /petalbot/i, name: 'Huawei', reason: search('Petal Search', 'Huawei’s search engine') },
  { ua: /dataforseo/i, name: 'DataForSEO', reason: seoData('DataForSEO') },
  { ua: /barkrowler|babbar/i, name: 'Babbar', reason: seoData('Babbar (Barkrowler)') },
  { ua: /mj12bot|majestic/i, name: 'Majestic', reason: seo('Majestic') },
  { ua: /dotbot|rogerbot/i, name: 'Moz', reason: seo('Moz') },
  { ua: /blexbot/i, name: 'BLEXBot', reason: seo('WebMeUp (BLEXBot)') },
  { ua: /sistrix/i, name: 'Sistrix', reason: seo('Sistrix') },
  {
    ua: /go-http-client/i,
    name: 'Go-http-client',
    reason:
      'The default name of Go’s HTTP library, not one crawler. Webhooks, uptime monitors and APIs send it, and so do scanners. Allow it only if a service you use sends it, and check the IP first.',
  },
  {
    ua: /(?:^|[\s(;])curl\//i,
    name: 'curl',
    reason:
      'curl, a command-line tool. Your own tests, uptime monitors, cron jobs and webhooks often send its default name; so do scripts and scanners. If you know what sent it, allow it; if not, leave it blocked.',
  },
  {
    ua: /censysinspect/i,
    name: 'Censys',
    reason:
      'Censys, a service that scans the whole internet to catalog servers. It does not index your pages for anyone to find. Most sites leave it blocked.',
  },
]

export function knownCrawler(userAgent: string): KnownCrawler | undefined {
  return KNOWN_CRAWLERS.find((c) => c.ua.test(userAgent))
}

export function judge(line: LogLine, groups: GroupResult[]): Verdict {
  const path = line.path ?? ''
  const ua = line.userAgent ?? ''

  const fp = KNOWN_FALSE_POSITIVES.find((k) => k.test(line, groups))
  if (fp) return v('false_positive', fp.reason)

  if (hits(groups, 'bad_bot', ATTACK_BOT_RULES)) {
    return v(
      'attack',
      'The user agent itself is attack text: a single character, encoded code, a web shell’s name or a shell command. No real browser or crawler sends that.',
    )
  }

  if (hits(groups, 'bad_request', PROBE_REQUEST_RULES) || ATTACK_PATHS.test(line.uri ?? path)) {
    return v(
      'attack',
      'This asks for a file no visitor needs: a web shell, a secrets or config file, a backup or a scanner’s favorite path. Bots try these on every site. 8G is doing its job.',
    )
  }

  const sql = hits(groups, 'bad_querystring', SEARCH_RULES) && SQL_SIGNS.test(line.queryString ?? '')
  if (sql || hits(groups, 'bad_querystring', ATTACK_QUERY_RULES) || hits(groups, 'bad_request', INJECTION_REQUEST_RULES)) {
    return v(
      'attack',
      'The address carries code: a file include, a PHP function name, SQL, or characters no real link has. It is an injection attempt, or a scraper following a broken link. Nothing a visitor needs is blocked.',
    )
  }

  if (hits(groups, 'bad_request', [28, 30])) {
    const served = /^2/.test(line.status)
    return v(
      served ? 'false_positive' : 'attack',
      served
        ? `Your site answered ${path} with ${line.status}, so it is a real page, and 8G blocks it for everyone: it blocks /old/, /backup/, /dev/, /site/, /staging/ and similar at the top of a site. Rename the page, or allow the rule.`
        : `Scanners ask for /old/, /backup/, /dev/, /site/ and similar to find a forgotten copy of a site. If ${path} is not a page on your site, leave it blocked; if it is, 8G blocks it for everyone.`,
    )
  }

  if (hits(groups, 'bad_request', [49])) {
    return v(
      'judgment',
      'WordPress’s XML-RPC file. Jetpack, the WordPress mobile app and some publishing tools use it; attackers use it to guess passwords. If you use none of those, leave it blocked.',
    )
  }

  if (hitNumbers(groups, 'bad_bot').length) {
    if (SCANNER_TOOLS.test(ua)) {
      return v(
        'attack',
        /mozlila/i.test(ua)
          ? 'A fake browser name: Mozlila is a misspelled Mozilla that bad bots send. No real browser does.'
          : 'An attack or vulnerability scanning tool. Unless you are running it against your own site, leave it blocked.',
      )
    }
    const known = knownCrawler(ua)
    if (known) return v('crawler', known.reason, known.name)
    return v(
      'crawler',
      '8G’s user agent rules are a crawler policy: they block names, not attacks. This one is on 8G’s list. If you know it and want it on your site, allow it; if you have never heard of it, leave it blocked.',
    )
  }

  if (hits(groups, 'bad_referer', [1, 2])) {
    return v(
      'attack',
      'The referrer carries SQL or PHP code, not the address of a page that linked here. Browsers never send that; attack tools do.',
    )
  }

  if (hitNumbers(groups, 'bad_referer').length) {
    return v(
      'judgment',
      '8G blocks visitors who arrive from a link whose address has spam words in it. If the linking site is real and the word is innocent there (a name, or another language: libido is Latin), it is a false positive; if it is spam, leave it blocked.',
    )
  }

  if (hitNumbers(groups, 'not_allowed_method').length) {
    return v(
      'attack',
      'Browsers and websites never send DEBUG, TRACE, TRACK, MOVE or CONNECT to a WordPress site; scanners and WebDAV tools do. Unless you use a WebDAV tool on this site, leave it blocked.',
    )
  }

  if (hitNumbers(groups, 'bad_cookie').length) {
    return v(
      'judgment',
      '8G blocks a request whose cookies hold < > or a quote mark, or an encoded line break or null. Your own site or a plugin can set such a cookie (a quote in a saved preference, for example): if logged-in visitors or shoppers get these, it is a false positive. If not, it is likely a probe. Cookies are not in the log, so check in the browser.',
    )
  }

  return v(
    'judgment',
    `Nothing here says attack or false positive for sure. If ${path || 'this address'} is a page, form or plugin on your site that people use, it is likely a false positive. If not, leave it blocked.`,
  )
}
