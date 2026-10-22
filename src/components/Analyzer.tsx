import { ArrowDown, Laptop, ScanSearch, Sparkles } from 'lucide-react'
import { useId, useRef, useState, type FormEvent } from 'react'
import { analyze, type LineResult } from '../lib/analyze'
import { RULESET_SOURCE } from '../lib/rules'
import { GROUPS } from '../lib/ruleset'
import { HeroDemo } from './HeroDemo'
import { ResultCard } from './ResultCard'

export const EXAMPLE =
  '[21/Oct/2026:06:25:38 +0000] [":bad_request_15:"] 203.0.113.20 example.com "GET /wp-json/rankmath/v1/getHead?url=https://example.com HTTP/2.0" 403 0.000 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"'

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
              <span className="statusline__seg statusline__seg--lead">GridPane 7G</span>
              <span className="statusline__seg">{`rules v${RULESET_SOURCE.version}`}</span>
              <span className="statusline__seg statusline__seg--extra">runs in your browser</span>
            </p>
            <h1>
              <span className="hero__line">7G Firewall</span>{' '}
              <span className="hero__line">
                <span className="accent-underline">Exception</span> Generator
              </span>
            </h1>
            <p className="lead">
              Paste a 7G log line to see the rule group and the exact pattern that fired. 7G Helper then writes an
              exception for that one request shape, in the place GridPane keeps through its updates. The rest of the
              firewall stays&nbsp;on.
            </p>
            <div className="hero__actions">
              <a className="button button--primary button--lg" href="#tool">
                Paste a log line
                <ArrowDown aria-hidden="true" />
              </a>
              <a className="button button--ghost button--lg" href="#how">
                How it works
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
              7g.log
            </span>
            <span className="window__meta mono" aria-live="polite">
              {lineCount === 0 ? 'empty' : `${lineCount} line${lineCount === 1 ? '' : 's'}`}
            </span>
          </div>
          <div className="tool__body">
            <h2 id="tool-title" className="tool__title">
              <label htmlFor={inputId}>Paste one or more lines from the 7G log</label>
            </h2>
            <p className="muted small" id={`${inputId}-where`}>
              The log is <code>/var/www/&lt;site&gt;/logs/7g.log</code> on the server.
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
              placeholder='[21/Oct/2026:06:25:38 +0000] [":bad_request_15:"] 203.0.113.7 example.com "GET /…'
              aria-describedby={empty ? `${inputId}-where ${inputId}-empty` : `${inputId}-where`}
            />
            {empty && (
              <p id={`${inputId}-empty`} className="field-error" role="alert">
                Paste at least one line from the 7G log first.
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
