import { Bot, FileCode2, Link2, ListFilter, Route, ScanSearch, Search, Waypoints } from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'
import type { GroupId } from '../lib/rules'
import { LINKS } from '../lib/links'
import { ExternalLink } from './ExternalLink'
import { GROUPS } from '../lib/ruleset'

export function HowItWorks() {
  const steps: { icon: typeof Search; title: string; body: ReactNode; cmd?: string }[] = [
    {
      icon: Search,
      title: 'Copy the line',
      body: <>Every 7G block is logged on the server. To see the latest for one site, run:</>,
      cmd: 'tail /var/www/<site>/logs/7g.log',
    },
    {
      icon: ScanSearch,
      title: 'See the rule',
      body: (
        <>
          You get the rule group and number, such as <code>bad_request_15</code>, its pattern, and the part of the
          request it matched.
        </>
      ),
    },
    {
      icon: FileCode2,
      title: 'Save the file',
      body: (
        <>
          A file for <code>/var/www/&lt;site&gt;/nginx/</code> turns off that one rule for that one address. Reload
          nginx, and two <code>curl</code> checks prove it.
        </>
      ),
    },
  ]
  return (
    <section className="section" id="how" aria-labelledby="how-title">
      <p className="eyebrow">How it works</p>
      <h2 id="how-title">From a 403 to a scoped fix in three steps</h2>
      <ol className="steps-grid">
        {steps.map((s, i) => (
          <li className="step-card" key={s.title}>
            <span className="step-card__num mono" aria-hidden="true">
              {String(i + 1).padStart(2, '0')}
            </span>
            <s.icon className="step-card__icon" aria-hidden="true" />
            <h3>{s.title}</h3>
            <p>{s.body}</p>
            {s.cmd && <code className="step-card__cmd">{s.cmd}</code>}
          </li>
        ))}
      </ol>
    </section>
  )
}

const GROUP_CARDS: { id: GroupId; icon: ComponentType<{ className?: string }>; title: string; what: string; often: string }[] = [
  {
    id: 'bad_request',
    icon: Route,
    title: 'Request URI',
    what: 'Paths and file names scanners try: secrets files, backups, shells, odd characters.',
    often: 'Plugin routes that carry a URL, like Rank Math’s getHead.',
  },
  {
    id: 'bad_querystring',
    icon: ListFilter,
    title: 'Query string',
    what: 'Injection patterns after the ?: SQL keywords, script tags, file paths.',
    often: 'OAuth sign-ins that redirect to localhost.',
  },
  {
    id: 'bad_bot',
    icon: Bot,
    title: 'User agent',
    what: 'Crawler names and script signatures in the user agent.',
    often: 'Link previews and SEO crawlers you actually want.',
  },
  {
    id: 'bad_referer',
    icon: Link2,
    title: 'Referrer',
    what: 'Known spam referrers and injection in the referring address.',
    often: 'Rare. GridPane sites can also have this group off.',
  },
  {
    id: 'not_allowed_method',
    icon: Waypoints,
    title: 'Method',
    what: 'Request methods a WordPress site never needs, such as TRACE and CONNECT.',
    often: 'Almost never: it answers 405, not 403.',
  },
]

export function RuleGroups() {
  return (
    <section className="section" id="rules" aria-labelledby="rules-title">
      <p className="eyebrow">What 7G checks</p>
      <h2 id="rules-title">Five rule groups, each reading one part of the request</h2>
      <p className="section__lead">
        A block is one pattern, in one group, matching one part of one request. The log names the group and the
        number, so the fix can be that narrow too.
      </p>
      <ul className="groups">
        {GROUP_CARDS.map((g) => {
          const group = GROUPS.get(g.id)!
          return (
            <li className="group-card" key={g.id}>
              <div className="group-card__head">
                <g.icon className="group-card__icon" />
                <h3>{g.title}</h3>
                <span className="group-card__count mono">{group.rules.length} rules</span>
              </div>
              <p className="group-card__vars mono">
                <span>${group.input}</span>
                <span aria-hidden="true">→</span>
                <span>${group.variable}</span>
              </p>
              <p>{g.what}</p>
              <p className="group-card__often">
                <span>Often blocks by mistake:</span> {g.often}
              </p>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

const FAQ: { q: string; a: React.ReactNode }[] = [
  {
    q: 'Does the log line I paste leave my browser?',
    a: 'No. Matching runs in your browser against a bundled copy of GridPane’s rules, and nothing you paste is sent or stored. Fathom counts visits without cookies and never sees your log lines.',
  },
  {
    q: 'Will a GridPane update remove the file?',
    a: (
      <>
        No. GridPane’s 7G config reads every <code>*-7g-context.conf</code> file in the site’s{' '}
        <code>nginx</code> folder and in <code>/etc/nginx/extra.d</code>, and updates leave them alone. See{' '}
        <ExternalLink href={LINKS.gridpaneDocs}>GridPane’s 7G guide</ExternalLink>.
      </>
    ),
  },
  {
    q: 'Why not turn the rule group off?',
    a: 'Turning a group off drops every rule in it, for every request to the site. The exception drops one rule, for one address or one crawler, and only when that rule is what fired. Everything else 7G checks stays on.',
  },
  {
    q: 'The rule number is not in GridPane’s list. What does that mean?',
    a: (
      <>
        It comes from a custom list on your server, which GridPane reads before its own rules. For a crawler, 7G Helper
        shows how to take its name off that list, which fixes every site on the server. The exception file works too,
        because it checks the number in your&nbsp;log.
      </>
    ),
  },
  {
    q: 'A request got a 403, but there is no line in 7g.log.',
    a: 'Then 7G did not block it. A 403 can also come from Cloudflare, ModSecurity, Fail2Ban or a security plugin, and an exception here will not change those.',
  },
  {
    q: 'Is this made by GridPane, or by the author of 7G?',
    a: (
      <>
        No. 7G is Jeff Starr’s firewall, published at <ExternalLink href={LINKS.perishable}>Perishable Press</ExternalLink>. GridPane ships
        its own modified version. 7G Helper is an independent tool, so review each file before you use it.
      </>
    ),
  },
]

export function Faq() {
  return (
    <section className="section" id="faq" aria-labelledby="faq-title">
      <p className="eyebrow">Questions</p>
      <h2 id="faq-title">Before you save the file</h2>
      <div className="faq">
        {FAQ.map((f) => (
          <details className="faq__item" key={f.q}>
            <summary>
              <span>{f.q}</span>
              <span className="faq__chevron" aria-hidden="true" />
            </summary>
            <div className="faq__answer">
              <p>{f.a}</p>
            </div>
          </details>
        ))}
      </div>
    </section>
  )
}
