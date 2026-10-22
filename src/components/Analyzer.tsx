import { ArrowDown, Laptop, ScanSearch, Sparkles } from 'lucide-react'
import { useId, useRef, useState, type FormEvent } from 'react'
import { analyze, type LineResult } from '../lib/ng/analyze'
import { RULESET_SOURCE } from '../lib/ng/rules'
import { GROUPS } from '../lib/ng/ruleset'
import { HeroDemo } from './HeroDemo'
import { ResultCard } from './ResultCard'

export const EXAMPLE =
  '2026-10-21T15:40:02+00:00 200 "GET /?s=how+to+get+started" cookie=0 method=0 referer=0 bot=0 querystring=39 request=0 ip=203.0.113.24 ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" ref="https://example.com/"'

export function Analyzer() {
  const [text, setText] = useState('')
  const [results, setResults] = useState<LineResult[] | null>(null)
  const [empty, setEmpty] = useState(false)
  const inputId = useId()
  const resultsRef = useRef<HTMLDivElement>(null)

  function run(value: string) {
    const r = analyze(value, GROUPS)
    setEmpty(r.length === 0)
    setResults(r.length ? r : null)
    if (r.length) requestAnimationFrame(() => resultsRef.current?.focus())
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    run(text)
  }

  function tryExample() {
    setText(EXAMPLE)
    run(EXAMPLE)
  }

  const lineCount = text.split('\n').filter((l) => l.trim()).length

  return (
    <>
      <section className="hero">
        <div className="hero__grid" aria-hidden="true">
          <span className="hero__glow" />
        </div>
        <div className="hero__inner">
          <div className="hero__copy">
            <p className="statusline mono">
              <span className="statusline__seg statusline__seg--lead">8G for nginx</span>
              <span className="statusline__seg">{`rules v${RULESET_SOURCE.version}`}</span>
              <span className="statusline__seg statusline__seg--extra">runs in your browser</span>
            </p>
            <h1>
              <span className="hero__line">8G Firewall</span>{' '}
              <span className="hero__line">
                <span className="accent-underline">Rule</span> Finder
              </span>
            </h1>
            <p className="lead">
              Paste an 8G log line to see the rule that fired, its exact pattern, and the text it matched. On GridPane,
              run 8G in watch mode beside 7G first, so you find the false positives before 8G blocks&nbsp;anything.
            </p>
            <div className="hero__actions">
              <a className="button button--primary button--lg" href="#tool">
                Paste a log line
                <ArrowDown aria-hidden="true" />
              </a>
              <a className="button button--ghost button--lg" href="#gridpane">
                Move from 7G to 8G
              </a>
            </div>
          </div>
          <HeroDemo />
        </div>
      </section>

      <section className="tool" id="tool" aria-labelledby="tool-title">
        <form className="window window--tool" onSubmit={submit}>
          <div className="window__bar">
            <span className="window__tab mono">
              <ScanSearch aria-hidden="true" />
              8g.log
            </span>
            <span className="window__meta mono" aria-live="polite">
              {lineCount === 0 ? 'empty' : `${lineCount} line${lineCount === 1 ? '' : 's'}`}
            </span>
          </div>
          <div className="tool__body">
            <h2 id="tool-title" className="tool__title">
              <label htmlFor={inputId}>Paste one or more lines from the 8G log</label>
            </h2>
            <p className="muted small" id={`${inputId}-where`}>
              On GridPane it is <code>/var/www/&lt;site&gt;/logs/8g.log</code>. A line from any access log works too.
            </p>
            <textarea
              id={inputId}
              data-testid="log-input"
              className="editor mono"
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              placeholder='2026-10-21T15:40:02+00:00 200 "GET /?s=…" cookie=0 method=0 referer=0 bot=0 querystring=39 …'
              aria-describedby={empty ? `${inputId}-where ${inputId}-empty` : `${inputId}-where`}
            />
            {empty && (
              <p id={`${inputId}-empty`} className="field-error" role="alert">
                Paste at least one log line first.
              </p>
            )}
            <div className="tool__footer">
              <div className="actions">
                <button type="submit" className="button button--primary" data-testid="log-submit">
                  <ScanSearch aria-hidden="true" />
                  Find the rule
                </button>
                <button type="button" className="button button--secondary" onClick={tryExample}>
                  <Sparkles aria-hidden="true" />
                  Try an example
                </button>
              </div>
              <p className="tool__private small">
                <Laptop aria-hidden="true" />
                Runs in your browser. Nothing you paste is sent anywhere.
              </p>
            </div>
          </div>
        </form>

        <div ref={resultsRef} tabIndex={-1} className="results" aria-live="polite">
          {results?.map((r, i) => <ResultCard key={i} result={r} />)}
        </div>
      </section>
    </>
  )
}
