import { CircleAlert, CircleCheck, FileCode2, MessageSquareText, OctagonX, Scale, TriangleAlert } from 'lucide-react'
import { useId, useState } from 'react'
import type { LineResult } from '../lib/analyze'
import { buildException, siteFolder, type Scope } from '../lib/exception'
import { buildListFix, findEntryCommand, type ListFix } from '../lib/listfix'
import type { RuleMatch } from '../lib/match'
import type { GroupId } from '../lib/rules'
import type { VerdictKind } from '../lib/verdict'
import { CodeLines } from './CodeLines'
import { CommandBlock, CopyButton, DownloadButton } from './CopyButton'

const GROUP_WORDS: Record<GroupId, { name: string; reads: string }> = {
  bad_bot: { name: 'User agent rules', reads: 'the name the browser or crawler sends' },
  bad_referer: { name: 'Referrer rules', reads: 'the page that linked here' },
  bad_querystring: { name: 'Query string rules', reads: 'everything after the ? in the address' },
  bad_request: { name: 'Request URI rules', reads: 'the address, with its query string' },
  not_allowed_method: { name: 'Method rules', reads: 'the request method, such as GET or POST' },
}

const VERDICT_ICON: Record<VerdictKind, typeof Scale> = { attack: OctagonX, false_positive: CircleCheck, judgment: Scale }

function Highlighted({ value, matched }: { value: string; matched?: RuleMatch['matched'] }) {
  if (!value) return <span className="muted">(empty)</span>
  if (!matched) return <>{value}</>
  const end = matched.index + matched.text.length
  return (
    <>
      {value.slice(0, matched.index)}
      <mark>{matched.text}</mark>
      {value.slice(end)}
    </>
  )
}

function RuleExplain({ m }: { m: RuleMatch }) {
  const words = GROUP_WORDS[m.hit.group]
  return (
    <section className="rule" data-testid="rule-result">
      <p className="rule__reads">
        7G read <code>${m.group.input}</code>, {words.reads}:
      </p>
      <p className="value mono">
        <Highlighted value={m.value} matched={m.matched} />
      </p>
      <div className="note note--rule">
        <p className="note__head">
          <MessageSquareText aria-hidden="true" />
          <code>{`${m.hit.group}_${m.hit.number}`}</code>
          <span>
            {words.name}, rule {m.hit.number}
          </span>
          {m.status !== 'matched' && (
            <span className={`tag tag--${m.status}`}>
              {m.status === 'custom' ? <CircleAlert aria-hidden="true" /> : <TriangleAlert aria-hidden="true" />}
              {m.status === 'custom' ? 'Custom list' : 'Not reproduced'}
            </span>
          )}
        </p>
        <div className="note__body">
          {m.status === 'matched' && m.rule && (
            <>
              <p>
                It matched <code className="hit">{m.matched!.text}</code> against this pattern in GridPane’s{' '}
                <code>7g-mappings.conf</code>:
              </p>
              <pre className="pattern mono" tabIndex={0} aria-label="The 7G pattern">
                <code>{`"~*${m.rule.source}" ${m.rule.number};`}</code>
              </pre>
            </>
          )}
          {m.status === 'custom' && (
            <>
              <p>
                GridPane’s shipped list has no rule {m.hit.number} in this group, so it comes from a custom list on your
                server, which GridPane reads first. To see the entry and the file it is in, run this on the&nbsp;server:
              </p>
              <CommandBlock code={findEntryCommand(m)} label="Find the custom entry" />
              <p className="muted small">
                The exception below still works: it checks for rule {m.hit.number}, the number in your log.
              </p>
            </>
          )}
          {m.status === 'unverified' && m.rule && (
            <>
              <p>
                Rule {m.hit.number} in GridPane’s current list does not match this request, so your server runs a
                different copy, or a custom list there reuses the number. This is the shipped rule {m.hit.number}:
              </p>
              <pre className="pattern mono" tabIndex={0} aria-label="The shipped 7G pattern">
                <code>{`"~*${m.rule.source}" ${m.rule.number};`}</code>
              </pre>
              <p className="muted small">
                The exception below still works: it checks for rule {m.hit.number}, the number in your log.
              </p>
            </>
          )}
        </div>
      </div>
    </section>
  )
}

function ScopeSwitch({ scope, setScope, site }: { scope: Scope; setScope: (s: Scope) => void; site: string }) {
  const name = useId()
  return (
    <fieldset className="segmented" data-value={scope}>
      <legend className="sr-only">Where should it apply?</legend>
      <span className="segmented__thumb" aria-hidden="true" />
      <label>
        <input type="radio" name={name} checked={scope === 'site'} onChange={() => setScope('site')} />
        <span>
          This site only <span className="segmented__sub mono">{site}</span>
        </span>
      </label>
      <label>
        <input type="radio" name={name} checked={scope === 'server'} onChange={() => setScope('server')} />
        <span>
          Every site <span className="segmented__sub mono">on this server</span>
        </span>
      </label>
    </fieldset>
  )
}

function ListFixPanel({ fix, number }: { fix: ListFix; number: number }) {
  return (
    <ol className="timeline" data-testid="list-fix">
      <li>
        <h4>Back up the list files</h4>
        <p>Run these on the server, not on your own computer. The copies go to /root, where nginx never reads them.</p>
        <CommandBlock code={fix.backup} label="Back up the list files" />
      </li>
      <li>
        <h4>Take the name off</h4>
        <CommandBlock code={fix.edit} label="Take the name off the list" />
        <p className="muted small">
          Only <code>{fix.token}</code> on lines numbered {number} changes. If it was the only name on its line, the line
          goes.
        </p>
      </li>
      <li>
        <h4>Check what is left</h4>
        <CommandBlock code={fix.find} label="Check the list" />
        <p className="muted small">
          <code>{fix.token}</code> should be gone and the other names still there. If it is still there, the list
          spells it another way: take it out by hand, in the file this names.
        </p>
      </li>
      <li>
        <h4>Check the config and reload nginx</h4>
        <CommandBlock code={fix.reload} label="Reload nginx" />
      </li>
      <li>
        <h4>Prove it both ways</h4>
        <p>From your own computer, send the request again. Anything but 403 means it now gets through:</p>
        <CommandBlock code={fix.testAllowed} label="Test that the request now passes" />
        <p>And this one should still come back 403, which shows the rest of 7G is on:</p>
        <CommandBlock code={fix.testStillBlocked} label="Test that 7G still blocks" />
      </li>
    </ol>
  )
}

function ExceptionPanel({ result }: { result: Extract<LineResult, { ok: true }> }) {
  const [scope, setScope] = useState<Scope>('site')
  const [today] = useState(() => new Date().toISOString().slice(0, 10))
  const file = buildException(result.line, result.matches, scope, today)
  const lines = file.content.replace(/\n$/, '').split('\n').length

  return (
    <div className="exception">
      <p className="exception__q">Where should it apply?</p>
      <ScopeSwitch scope={scope} setScope={setScope} site={siteFolder(result.line.host)} />

      <ol className="timeline">
        <li>
          <h4>Save this file on the server</h4>
          <p className="path-line">
            <code className="path" data-testid="exception-path">
              {file.path}
            </code>
          </p>
          <div className="window window--file">
            <div className="window__bar">
              <span className="window__tab mono">
                <FileCode2 aria-hidden="true" />
                {file.fileName}
              </span>
              <span className="window__actions">
                <CopyButton text={file.content} label="Copy file" />
                <DownloadButton text={file.content} fileName={file.fileName} />
              </span>
            </div>
            <CodeLines code={file.content} language="nginx" numbered label={`The file ${file.fileName}`} testId="exception-file" />
            <div className="window__status mono">
              <span>nginx</span>
              <span>{lines} lines</span>
              <span>{scope === 'site' ? 'per site' : 'server-wide'}</span>
            </div>
          </div>
          {scope === 'site' && (
            <p className="muted small">
              If that folder does not exist, run <code>ls /var/www</code> and use the site’s folder name.
            </p>
          )}
        </li>
        <li>
          <h4>Check the config and reload nginx</h4>
          <CommandBlock code={file.reload} label="Reload nginx" />
        </li>
        <li>
          <h4>Prove it both ways</h4>
          <p>Send the request again. Anything but 403 means it now gets through:</p>
          <CommandBlock code={file.testAllowed} label="Test that the request now passes" />
          <p>And this one should still come back 403, which shows the rest of 7G is on:</p>
          <CommandBlock code={file.testStillBlocked} label="Test that 7G still blocks" />
        </li>
      </ol>
    </div>
  )
}

export function ResultCard({ result }: { result: LineResult }) {
  const [today] = useState(() => new Date().toISOString().slice(0, 10))
  if (!result.ok) {
    return (
      <article className="card card--error" role="alert" data-testid="no-rule-message">
        <div className="card__error">
          <TriangleAlert aria-hidden="true" />
          <div>
            <h2>We could not read this line</h2>
            <p>{result.reason}</p>
          </div>
        </div>
        <p className="value mono">{result.raw.length > 300 ? `${result.raw.slice(0, 300)}…` : result.raw}</p>
      </article>
    )
  }

  const { line, matches, verdict } = result
  const several = matches.length > 1
  const Icon = VERDICT_ICON[verdict.kind]
  const listFix = verdict.kind === 'attack' ? undefined : buildListFix(line, matches, today)

  return (
    <article className="card">
      <header className="card__head">
        <p className="request mono">
          <span className="request__method">{line.method || '?'}</span> {line.uri}
        </p>
        <p className="meta mono">
          <span>{line.host}</span>
          <span>{line.time}</span>
          <span>{line.ip}</span>
          {line.status && <span className="meta__status">{line.status}</span>}
        </p>
      </header>

      <div className={`verdict verdict--${verdict.kind}`}>
        <Icon className="verdict__icon" aria-hidden="true" />
        <div>
          <h2>{verdict.title}</h2>
          <p>{verdict.reason}</p>
        </div>
      </div>

      <div className="rules">
        <p className="rules__lead">
          {several
            ? `${matches.length} rules blocked this request. The exception has to cover all of them.`
            : 'One rule blocked this request.'}
        </p>
        {matches.map((m) => (
          <RuleExplain key={`${m.hit.group}_${m.hit.number}`} m={m} />
        ))}
      </div>

      <section className="exception-wrap">
        {verdict.kind === 'attack' ? (
          <details className="fold">
            <summary>
              <span>Write an exception anyway</span>
              <span className="faq__chevron" aria-hidden="true" />
            </summary>
            <ExceptionPanel result={result} />
          </details>
        ) : listFix ? (
          <>
            <h2>Take it off your list</h2>
            <p>
              Rule {matches[0].hit.number} is a line someone added to this server’s own list, often to block AI
              crawlers. Taking <code>{listFix.token}</code> off it fixes every site on the server, and the other names on
              that line stay&nbsp;blocked.
            </p>
            <ListFixPanel fix={listFix} number={matches[0].hit.number} />
            <h2 className="exception-wrap__alt">Or keep the list: the exception file</h2>
            <p>
              If the list should still block this crawler on your other sites, leave it alone and let it through where
              you need it.
            </p>
            <ExceptionPanel result={result} />
          </>
        ) : (
          <>
            <h2>The exception file</h2>
            <p>
              It lets this one request shape through, only when {several ? 'these rules are' : 'this rule is'} what
              blocked it. The rest of 7G stays on.
            </p>
            <ExceptionPanel result={result} />
          </>
        )}
      </section>
    </article>
  )
}
