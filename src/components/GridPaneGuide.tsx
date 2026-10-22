import { Eye, ShieldCheck, Terminal, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { RUNBOOK } from '../content/runbook'
import { LINKS } from '../lib/links'
import { CodeLines } from './CodeLines'
import { CopyButton } from './CopyButton'
import { ExternalLink } from './ExternalLink'

/** A shell block in a fold, closed until asked for, so the steps read as one short list first. */
function Commands({ code, name, label = 'Show the commands' }: { code: string; name: string; label?: string }) {
  return (
    <details className="fold guide-fold">
      <summary>
        <span>{label}</span>
        <span className="faq__chevron" aria-hidden="true" />
      </summary>
      <div className="window window--file">
        <div className="window__bar">
          <span className="window__tab mono">
            <Terminal aria-hidden="true" />
            {name}
          </span>
          <span className="window__actions">
            <CopyButton text={code} label="Copy" />
          </span>
        </div>
        <CodeLines code={code} language="shell" label={`Commands: ${name}`} />
      </div>
    </details>
  )
}

const STEPS: { title: string; body: ReactNode; code: string; name: string }[] = [
  {
    title: 'Check the server',
    body: (
      <>
        Read-only. It confirms nginx (not OpenLiteSpeed), that GridPane loads the site’s own config files, and that
        nginx records the visitor’s real address behind Cloudflare.
      </>
    ),
    code: RUNBOOK.check,
    name: 'step 0: check',
  },
  {
    title: 'Download the rules',
    body: (
      <>
        Two files from nG-SetEnvIf, pinned to one commit of 8G v1.5, saved in an <code>8g</code> folder inside the
        site’s <code>nginx</code> folder. Nothing loads them yet.
      </>
    ),
    code: RUNBOOK.download,
    name: 'step 1: download',
  },
  {
    title: 'Turn on watch mode',
    body: (
      <>
        Two small files: one loads the rules and sets the log format, one checks each request and logs what 8G would
        block. If <code>nginx -t</code> fails, the step removes its own files and reloads nothing.
      </>
    ),
    code: RUNBOOK.watch,
    name: 'step 2: watch mode',
  },
  {
    title: 'Check that it works',
    body: (
      <>
        A request with curl’s own user agent, which 7G allows and 8G would block, should land in the 8G log a few
        seconds later. The site still answers it normally.
      </>
    ),
    code: RUNBOOK.verify,
    name: 'step 3: check',
  },
  {
    title: 'Read the log for a week or two',
    body: (
      <>
        Count which rules fire, then paste the lines into 8G Helper above. Each one is an attack, or a person, plugin
        or service you want. Every “want” is a false positive to fix before you enforce.
      </>
    ),
    code: RUNBOOK.read,
    name: 'step 4: read the log',
  },
  {
    title: 'Enforce, on staging first',
    body: (
      <>
        Swap the watch file for the enforce file, prove it blocks, then turn 7G off for that site in GridPane. Try
        everything a person does on the site, then move on to one low-risk live site.
      </>
    ),
    code: `${RUNBOOK.enforce}\n\n# a few seconds later\n${RUNBOOK.prove}`,
    name: 'step 5: enforce',
  },
]

const EXPECT: ReactNode[] = [
  <>
    <strong>Crawlers, more than attacks.</strong> On real sites most of what 8G would add came from search and AI
    crawlers in its <code>bot</code> rules. Those rules are a choice about which crawlers you want, not attack&nbsp;signatures.
  </>,
  <>
    <strong>Your own tools.</strong> <code>bot</code> rule 3 blocks <code>curl</code>, <code>scan</code> and{' '}
    <code>ahrefs</code>: uptime monitors, cron jobs, a payment provider’s security scanner, Ahrefs Site Audit, and
    your own&nbsp;tests.
  </>,
  <>
    <strong>Site search.</strong> <code>querystring</code> rule 39 blocks searches containing words such as{' '}
    <code>get</code>, <code>select</code> or <code>delete</code> between other&nbsp;words.
  </>,
  <>
    <strong>AI agents that sign in.</strong> <code>querystring</code> rule 9 blocks <code>localhost</code> in a query
    string, which OAuth sign-ins for MCP connectors send. Don’t enforce on a site an agent connects to without an&nbsp;exception.
  </>,
  <>
    <strong>The real catch.</strong> Probes for shells, backups and config files that 7G let through, nearly all
    answered 404&nbsp;already.
  </>,
]

export function GridPaneGuide() {
  return (
    <section className="section" id="gridpane" aria-labelledby="gridpane-title">
      <p className="eyebrow">7G to 8G on GridPane</p>
      <h2 id="gridpane-title">Run 8G beside 7G first, then switch</h2>
      <p className="section__lead">
        GridPane has no 8G switch: its 7G toggle is GridPane’s own build of 7G. On its nginx you run{' '}
        <ExternalLink href={LINKS.ngSetEnvIf}>nG-SetEnvIf</ExternalLink>, the nginx version of 8G. Watch mode lets 8G
        log what it would block for a week or two while 7G keeps protecting the&nbsp;site.
      </p>

      <ul className="modes">
        <li className="mode-card">
          <div className="mode-card__head">
            <Eye className="mode-card__icon" aria-hidden="true" />
            <h3>Watch</h3>
            <span className="mode-card__tag mono">safe on a live site</span>
          </div>
          <p>8G checks every request and logs what it would block. It blocks nothing, and 7G stays on.</p>
          <p className="mode-card__fine">
            It can’t see static files, which GridPane doesn’t log, or anything 7G blocks first. So the log shows what 8G
            would add on top of 7G.
          </p>
        </li>
        <li className="mode-card">
          <div className="mode-card__head">
            <ShieldCheck className="mode-card__icon" aria-hidden="true" />
            <h3>Enforce</h3>
            <span className="mode-card__tag mono">staging first</span>
          </div>
          <p>8G blocks, with a 403, or a 405 for a method it refuses. Turn 7G off for that site once 8G is on.</p>
          <p className="mode-card__fine">Jeff Starr’s advice is to run 7G or 8G on a site, not both.</p>
        </li>
      </ul>

      <ol className="guide-steps">
        {STEPS.map((s, i) => (
          <li className="guide-step" key={s.title}>
            <span className="guide-step__num mono" aria-hidden="true">
              {String(i).padStart(2, '0')}
            </span>
            <div className="guide-step__body">
              <h3>{s.title}</h3>
              <p>{s.body}</p>
              <Commands code={s.code} name={s.name} />
            </div>
          </li>
        ))}
      </ol>

      <div className="note guide-note">
        <div className="note__head">
          <TriangleAlert aria-hidden="true" />
          <span>The rules are shared across the server</span>
        </div>
        <div className="note__body">
          <p>
            nginx keeps one set of 8G rules per server, so when two sites each have a copy, the copy loaded last applies to
            both. Keep every copy on a server identical, and never edit one site’s copy alone.
          </p>
        </div>
      </div>

      <h3 className="guide-subhead">What the logs showed on real sites</h3>
      <ul className="expect">
        {EXPECT.map((e, i) => (
          <li key={i}>{e}</li>
        ))}
      </ul>

      <div className="guide-undo">
        <Commands code={RUNBOOK.undo} name="undo" label="Undo: take 8G off a site" />
      </div>
    </section>
  )
}
