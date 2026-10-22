import {
  Bot,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  FileCode2,
  MessageSquareText,
  OctagonX,
  Scale,
  Terminal,
  TriangleAlert,
} from 'lucide-react'
import { useId, useState } from 'react'
import { buildAllowCommands, findCopiesCommand, parseCopies, planAllow, ruleText, type AllowWarning } from '../lib/ng/allowfix'
import type { LineResult, Mode } from '../lib/ng/analyze'
import { printable } from '../lib/ng/logline'
import type { CheckStatus, GroupResult, RuleMatch } from '../lib/ng/match'
import type { GroupId, Rule } from '../lib/ng/rules'
import type { VerdictKind } from '../lib/ng/verdict'
import { bindLast } from '../lib/text'
import { CodeLines } from './CodeLines'
import { CommandBlock, CopyButton } from './CopyButton'

type Ok = Extract<LineResult, { ok: true }>

const GROUP_WORDS: Record<GroupId, { name: string; reads: string }> = {
  bad_cookie: { name: 'Cookie rules', reads: 'the cookies the browser sends' },
  not_allowed_method: { name: 'Method rules', reads: 'the request method, such as GET or POST' },
  bad_referer: { name: 'Referrer rules', reads: 'the page that linked here' },
  bad_bot: { name: 'User agent rules', reads: 'the name the browser or crawler sends' },
  bad_querystring: { name: 'Query string rules', reads: 'everything after the ? in the address, exactly as sent' },
  bad_request: { name: 'Request path rules', reads: 'the address without its query string, decoded' },
}

const MODE_TAG: Record<Mode, string> = {
  enforce: 'blocked by 8G',
  watch: 'watch mode: logged only',
  unknown: 'access log line',
}

const VERDICT_ICON: Record<VerdictKind, typeof Scale> = {
  attack: OctagonX,
  false_positive: CircleCheck,
  crawler: Bot,
  judgment: Scale,
}

const CHECK_TAG: Record<CheckStatus, { text: string; icon: typeof Scale }> = {
  confirmed: { text: 'Checked', icon: CircleCheck },
  unchecked: { text: 'Not checked', icon: CircleHelp },
  mismatch: { text: 'Not stock 8G v1.5', icon: CircleAlert },
}

/** The value with the matched text marked. Values are byte strings, so each part is made printable on its own. */
function Highlighted({ value, matched }: { value: string; matched?: RuleMatch['matched'] }) {
  if (!value) return <span className="muted">(empty)</span>
  if (!matched) return <>{printable(value)}</>
  const end = matched.index + matched.text.length
  return (
    <>
      {printable(value.slice(0, matched.index))}
      <mark>{printable(matched.text)}</mark>
      {printable(value.slice(end))}
    </>
  )
}

function RuleLine({ rule }: { rule: Rule }) {
  return (
    <div className="window window--file rule-line">
      <div className="window__bar">
        <span className="window__tab mono">
          <FileCode2 aria-hidden="true" />
          8g-firewall.conf
        </span>
        <span className="window__meta mono">line {rule.line}</span>
      </div>
      <CodeLines code={ruleText(rule)} language="nginx" wrap label={`The 8G pattern on line ${rule.line}`} />
    </div>
  )
}

/** The rule this group names: the one the line logged, or the first that matches. */
function named(g: GroupResult): number | undefined {
  return g.logged || g.matches.find((m) => m.first)?.rule.number
}

function GroupExplain({ g }: { g: GroupResult }) {
  const words = GROUP_WORDS[g.group.id]
  const number = named(g)!
  const rule = g.loggedRule ?? g.group.rules.find((r) => r.number === number)
  const hit = g.matches.find((m) => m.rule.number === number && !m.inCut)
  const others = g.matches.filter((m) => m !== hit)
  const tag = g.check && CHECK_TAG[g.check.status]

  return (
    <section className="rule" data-testid="rule-result">
      <p className="rule__reads">
        8G read <code>${g.group.input}</code>, {words.reads}:
      </p>
      {g.value === undefined ? (
        <p className="value value--missing">
          {g.group.id === 'bad_cookie' ? 'Cookies are never in the log, so this part can’t be shown.' : 'The line does not include this part.'}
        </p>
      ) : (
        <p className="value mono">
          <Highlighted value={g.value} matched={hit?.matched} />
        </p>
      )}
      <div className="note note--rule">
        <p className="note__head">
          <MessageSquareText aria-hidden="true" />
          <code>{`${g.group.field} ${number}`}</code>
          <span>
            {words.name}, rule {number}
          </span>
          {tag && (
            <span className={`tag tag--${g.check!.status}`}>
              <tag.icon aria-hidden="true" />
              {tag.text}
            </span>
          )}
        </p>
        <div className="note__body">
          {hit ? (
            <p>
              It matched <code className="hit">{printable(hit.matched.text)}</code> against this pattern:
            </p>
          ) : rule ? (
            <p>This is the pattern 8G v1.5 has for it:</p>
          ) : null}
          {rule && <RuleLine rule={rule} />}
          {g.check && g.check.status !== 'confirmed' && <p className="muted small">{bindLast(g.check.note)}</p>}
          {others.length > 0 && (
            <div className="also">
              <p className="small">
                nginx stops at the first match, so the log names one rule. {others.length === 1 ? 'This one matches' : 'These match'}{' '}
                too, and {others.length === 1 ? 'blocks' : 'block'} the request once rule {number} is allowed:
              </p>
              <ul>
                {others.map((m) => (
                  <li key={m.rule.number}>
                    <code>{`${g.group.field} ${m.rule.number}`}</code> matched <code className="hit">{printable(m.matched.text)}</code>{' '}
                    <span className="muted">line&nbsp;{m.rule.line}</span>
                    {m.inCut && <span className="muted"> (only in the shortened part of the line, so maybe&nbsp;not)</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function Warnings({ warnings }: { warnings: AllowWarning[] }) {
  return (
    <ul className="warnings">
      {warnings.map((w) => (
        <li key={w.text}>
          <TriangleAlert aria-hidden="true" />
          <span>{bindLast(w.text)}</span>
        </li>
      ))}
    </ul>
  )
}

function ShellWindow({ code, name }: { code: string; name: string }) {
  return (
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
  )
}

/** nG's documented interim fix, for every group that blocks the request, in three steps that never edit through a glob. */
function AllowPanel({ result }: { result: Ok }) {
  const [pasted, setPasted] = useState('')
  const [today] = useState(() => new Date().toISOString().slice(0, 10))
  const pasteId = useId()

  const plans = result.groups.flatMap((g) => planAllow(g, result.groups) ?? [])
  const edits = plans.flatMap((p) => p.edits)
  if (!edits.length) return <p className="muted">There is no rule to edit for this line.</p>

  // One plan covers every group that blocks, so "another group still blocks it" no longer applies.
  const seen = new Set<string>()
  const warnings = plans
    .flatMap((p) => p.warnings)
    .filter((w) => !(plans.length > 1 && w.code === 'other_groups'))
    .filter((w) => !seen.has(w.text) && seen.add(w.text))

  const listing = pasted.trim() ? parseCopies(pasted, edits) : undefined
  let commands: ReturnType<typeof buildAllowCommands> | undefined
  let failed: string | undefined
  if (listing && !listing.problems.length && listing.copies.length) {
    try {
      commands = buildAllowCommands(edits, listing.copies, today)
    } catch (e) {
      failed = e instanceof Error ? e.message : String(e)
    }
  }

  return (
    <div className="allow" data-testid="allow-fix">
      <ul className="edits">
        {edits.map((e) => (
          <li key={`${e.rule.group}_${e.rule.number}`}>
            <p className="edits__what">
              <code>{`${e.rule.group.replace(/^bad_|^not_allowed_/, '')} ${e.rule.number}`}</code>{' '}
              {e.kind === 'remove' ? (
                <>
                  take out{' '}
                  {e.tokens.map((t, i) => (
                    <span key={t}>
                      {i > 0 && ' and '}
                      <code className="hit">{t}</code>
                    </span>
                  ))}
                </>
              ) : (
                'comment out the whole rule'
              )}
            </p>
            <pre className="diff mono" tabIndex={0} aria-label={`The change to line ${e.rule.line}`}>
              <code>
                <span className="diff__del">- {e.before}</span>
                {'\n'}
                <span className="diff__ins">+ {e.after}</span>
              </code>
            </pre>
          </li>
        ))}
      </ul>

      <Warnings warnings={warnings} />

      <ol className="timeline">
        <li>
          <h4>List every copy on the server</h4>
          <p>
            Run this on the server as root. It changes nothing: it prints each copy of <code>8g-firewall.conf</code> and
            the line each rule is on.
          </p>
          <CommandBlock code={findCopiesCommand(edits)} label="List every copy of the rules" />
        </li>
        <li>
          <h4>
            <label htmlFor={pasteId}>Paste what it printed</label>
          </h4>
          <textarea
            id={pasteId}
            data-testid="copies-input"
            className="editor editor--short mono"
            value={pasted}
            onChange={(e) => setPasted(e.target.value)}
            rows={3}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            placeholder="/var/www/example.com/nginx/8g/8g-firewall.conf:130:…"
          />
          {listing && listing.problems.length > 0 && (
            <ul className="field-error copies-problems" role="alert">
              {listing.problems.map((p) => (
                <li key={p}>{bindLast(p)}</li>
              ))}
            </ul>
          )}
          {failed && (
            <p className="field-error" role="alert">
              {bindLast(failed)}
            </p>
          )}
          {listing && !listing.problems.length && (
            <div className="copies" data-testid="copies">
              <p className="small">
                {listing.copies.length} {listing.copies.length === 1 ? 'copy' : 'copies'}, every one as 8G v1.5 ships it:
              </p>
              <ul className="mono small">
                {listing.copies.map((c) => (
                  <li key={c.file}>
                    {c.file} <span className="muted">line&nbsp;{c.lines.join(', ')}</span>
                  </li>
                ))}
              </ul>
              {listing.notes.map((n) => (
                <p className="muted small" key={n}>
                  {bindLast(n)}
                </p>
              ))}
            </div>
          )}
        </li>
        <li>
          <h4>Edit every copy</h4>
          {commands ? (
            <>
              <p>
                It backs up each copy, makes the edit, checks each changed line, and reloads nginx only if{' '}
                <code>nginx -t</code> passes. If anything fails, it puts every copy back.
              </p>
              <ShellWindow code={commands.edit} name="edit every copy" />
            </>
          ) : (
            <p className="muted">The command appears here once the list is pasted&nbsp;above.</p>
          )}
        </li>
        <li>
          <h4>Check it</h4>
          {commands ? (
            <>
              <p>Each copy should print the edited line:</p>
              <CommandBlock code={commands.verify} label="Show the edited lines" />
              <p>
                Then send the request again. A few seconds later it should no longer be added&nbsp;to{' '}
                <code>8g.log</code>.
              </p>
              <details className="fold">
                <summary>
                  <span>Undo it later</span>
                  <span className="faq__chevron" aria-hidden="true" />
                </summary>
                <p className="small">
                  Puts every copy back from its backup (<code>{commands.backupSuffix}</code>) and reloads nginx.
                </p>
                <ShellWindow code={commands.restore} name="undo the edit" />
              </details>
            </>
          ) : (
            <p className="muted">Then a read-only check, and how to undo&nbsp;it.</p>
          )}
        </li>
      </ol>
    </div>
  )
}

function lead(result: Ok): string {
  const { fired, mode, line } = result
  if (!fired) return ''
  const name = `${fired.group.field} rule ${fired.number}`
  switch (mode) {
    case 'enforce':
      return `8G blocked this request with ${name}${line.status ? ` (${line.status})` : ''}.`
    case 'watch':
      return `8G would block this request with ${name}. Watch mode only logged it${line.status ? `, and the request got ${line.status}` : ''}.`
    default:
      return `An access log line doesn’t say what 8G did. With 8G on, ${name} would block this request.`
  }
}

export function ResultCard({ result }: { result: LineResult }) {
  if (!result.ok) {
    return (
      <article className="card card--error" role="alert" data-testid="no-rule-message">
        <div className="card__error">
          <TriangleAlert aria-hidden="true" />
          <div>
            <h2>We could not read this line</h2>
            <p>{bindLast(result.reason)}</p>
          </div>
        </div>
        <p className="value mono">{result.raw.length > 300 ? `${result.raw.slice(0, 300)}…` : result.raw}</p>
      </article>
    )
  }

  const { line, verdict, mode } = result
  const shown = result.groups.filter((g) => named(g) !== undefined)
  const Icon = verdict ? VERDICT_ICON[verdict.kind] : CircleCheck

  return (
    <article className="card" data-testid="result-card">
      <header className="card__head">
        <p className="request mono">
          {line.method && <span className="request__method">{line.method}</span>} {printable(line.requestUri ?? line.path ?? '')}
        </p>
        <p className="meta mono">
          {line.time && <span>{line.time}</span>}
          {line.ip && <span>{line.ip}</span>}
          {line.status && <span className="meta__status">{line.status}</span>}
          <span className={`mode-tag mode-tag--${mode}`} data-testid="mode">
            {result.fired ? MODE_TAG[mode] : 'nothing fired'}
          </span>
        </p>
      </header>

      {verdict ? (
        <div className={`verdict verdict--${verdict.kind}`} data-testid="verdict">
          <Icon className="verdict__icon" aria-hidden="true" />
          <div>
            <h2>
              {verdict.title}
              {verdict.crawler && <span className="verdict__name">:&nbsp;{verdict.crawler}</span>}
            </h2>
            <p>{bindLast(verdict.reason)}</p>
          </div>
        </div>
      ) : (
        <div className="verdict verdict--clear" data-testid="verdict">
          <Icon className="verdict__icon" aria-hidden="true" />
          <div>
            <h2>8G lets this through</h2>
            <p>{bindLast(result.nothing ?? '')}</p>
          </div>
        </div>
      )}

      {shown.length > 0 && (
        <div className="rules">
          <p className="rules__lead">
            {bindLast(
              `${lead(result)}${shown.length > 1 ? ` ${shown.length} groups match it, and each one has to be allowed before it gets through.` : ''}`,
            )}
          </p>
          {shown.map((g) => (
            <GroupExplain key={g.group.id} g={g} />
          ))}
        </div>
      )}

      {verdict && (
        <section className="exception-wrap">
          {verdict.kind === 'attack' ? (
            <details className="fold">
              <summary>
                <span>Allow it anyway</span>
                <span className="faq__chevron" aria-hidden="true" />
              </summary>
              <AllowPanel result={result} />
            </details>
          ) : (
            <>
              <h2>{verdict.kind === 'crawler' ? 'Allow this crawler for now' : 'Allow it for now'}</h2>
              <p>
                8G has no exception files yet, so the documented fix is to edit the rule itself, in every copy of{' '}
                <code>8g-firewall.conf</code> on the server: take out the name that matched, or comment out the rule. A
                scoped exception for one site comes once enforce mode has been&nbsp;tested.
                {mode === 'watch' && ' Watch mode blocks nothing, so there is no hurry: do it before this site enforces\u00a08G.'}
              </p>
              <AllowPanel result={result} />
            </>
          )}
        </section>
      )}
    </article>
  )
}
