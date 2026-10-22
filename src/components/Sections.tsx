import { Bot, Cookie, Link2, ListFilter, Route, Scale, ScanSearch, Search, Waypoints } from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'
import type { GroupId } from '../lib/ng/rules'
import { LINKS } from '../lib/links'
import { ExternalLink } from './ExternalLink'
import { GROUPS } from '../lib/ng/ruleset'

export function HowItWorks() {
  const steps: { icon: typeof Search; title: string; body: ReactNode; cmd?: string }[] = [
    {
      icon: Search,
      title: 'Copy the line',
      body: (
        <>
          8G logs every request it blocks, or in watch mode would block, with the rule that fired. A line from any
          nginx or Apache access log works too. For the latest from one site:
        </>
      ),
      cmd: 'tail /var/www/<site>/logs/8g.log',
    },
    {
      icon: ScanSearch,
      title: 'See the rule',
      body: (
        <>
          You get the group and number, such as <code>bot=3</code>, its pattern, the text it matched, and any other
          rule in that group that matches too.
        </>
      ),
    },
    {
      icon: Scale,
      title: 'Decide',
      body: (
        <>
          An attack, or something you want? For something you want, you get the documented way to let it through for
          now, and what it costs.
        </>
      ),
    },
  ]
  return (
    <section className="section" id="how" aria-labelledby="how-title">
      <p className="eyebrow">How it works</p>
      <h2 id="how-title">From a log line to the exact rule in three steps</h2>
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
    id: 'bad_querystring',
    icon: ListFilter,
    title: 'Query string',
    what: 'Injection after the ?: SQL keywords, script tags, file paths, encoded slashes. Read exactly as sent.',
    often: 'Site searches with words like get or select, and OAuth sign-ins that send localhost.',
  },
  {
    id: 'bad_request',
    icon: Route,
    title: 'Request path',
    what: 'Paths scanners try: shells, backups, config files, odd characters. Read decoded, without the query string.',
    often: 'A real page whose address looks like one, such as /backup/.',
  },
  {
    id: 'bad_bot',
    icon: Bot,
    title: 'User agent',
    what: 'Scanner and script names, fake browser names, and some crawlers.',
    often: 'Crawlers you want, uptime monitors and curl, a payment provider’s security scanner.',
  },
  {
    id: 'bad_referer',
    icon: Link2,
    title: 'Referrer',
    what: 'Spam and injection in the referring address.',
    often: 'Rare.',
  },
  {
    id: 'bad_cookie',
    icon: Cookie,
    title: 'Cookie',
    what: 'Injection hidden in a cookie.',
    often: 'Rare. The log names the rule but never records the cookie itself.',
  },
  {
    id: 'not_allowed_method',
    icon: Waypoints,
    title: 'Method',
    what: 'Methods a WordPress site never needs, such as TRACE and CONNECT.',
    often: 'Almost never. It answers 405, and nginx refuses TRACE on its own first.',
  },
]

export function RuleGroups() {
  return (
    <section className="section" id="rules" aria-labelledby="rules-title">
      <p className="eyebrow">What 8G checks</p>
      <h2 id="rules-title">Six rule groups, each reading one part of the request</h2>
      <p className="section__lead">
        nginx reads each group as a list and stops at the first pattern that matches, so the log names one rule per
        group. 8G Helper checks the whole list, so a second match can’t surprise you after the first is&nbsp;fixed.
      </p>
      <ul className="groups">
        {GROUP_CARDS.map((g) => {
          const group = GROUPS.get(g.id)!
          return (
            <li className="group-card" key={g.id}>
              <div className="group-card__head">
                <g.icon className="group-card__icon" />
                <h3>{g.title}</h3>
                <span className="group-card__count mono">
                  {group.rules.length} rule{group.rules.length === 1 ? '' : 's'}
                </span>
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
    a: 'No. Matching runs in your browser against a bundled copy of 8G v1.5 from nG-SetEnvIf, and nothing you paste is sent or stored.',
  },
  {
    q: 'What is watch mode?',
    a: (
      <>
        A way to try 8G on a live site without risk: 8G checks every request and logs what it would block, while 7G keeps
        blocking. It is two small files in the site’s own nginx folder. See <a href="#gridpane">7G to 8G</a>.
      </>
    ),
  },
  {
    q: 'Why is there no exception file, like 7G Helper’s?',
    a: (
      <>
        On GridPane, 7G reads update-safe exception files and has a switch for each rule group. 8G has neither yet, and
        its rules are one shared set per server. Until a scoped exception has been tested in enforce mode, 8G Helper
        gives the documented fix: comment out the rule, or remove the one word that matched, in every copy on
        the&nbsp;server.
      </>
    ),
  },
  {
    q: 'Will a GridPane update remove 8G?',
    a: 'No. Everything lives in the site’s own nginx folder, which updates leave alone. Downloading a newer 8G replaces the rules, along with any line you commented out, so redo those edits after.',
  },
  {
    q: 'A request got a 403, but no 8G rule matches it.',
    a: 'Then 8G did not block it. A 403 can also come from 7G, Cloudflare, Fail2Ban or a security plugin. In watch mode, 7G runs first, so anything it blocks never reaches the 8G log.',
  },
  {
    q: 'Is this made by GridPane, or by the author of 8G?',
    a: (
      <>
        No. 8G is Jeff Starr’s firewall, published at <ExternalLink href={LINKS.eightG}>Perishable Press</ExternalLink>.
        nG-SetEnvIf, the nginx version, is by Tonkünstler-on-the-Bund. 8G Helper is an independent tool, so check each
        change before you make&nbsp;it.
      </>
    ),
  },
  {
    q: 'What about Apache?',
    a: 'Jeff’s official 8G is for Apache. An Apache version of this tool comes next, tested against real Apache before it ships.',
  },
]

export function Faq() {
  return (
    <section className="section" id="faq" aria-labelledby="faq-title">
      <p className="eyebrow">Questions</p>
      <h2 id="faq-title">Before you change anything</h2>
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
