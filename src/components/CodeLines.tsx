import { highlightNginx, highlightShell } from '../lib/highlight'

/** Highlighted code, one row per line, with optional line numbers. The text copies exactly as written. */
export function CodeLines({
  code,
  language,
  numbered = false,
  wrap = false,
  label,
  testId,
}: {
  code: string
  language: 'nginx' | 'shell'
  numbered?: boolean
  wrap?: boolean
  label?: string
  testId?: string
}) {
  const lines = language === 'nginx' ? highlightNginx(code) : highlightShell(code)
  return (
    <pre
      className={`code${numbered ? ' code--numbered' : ''}${wrap ? ' code--wrap' : ''}`}
      tabIndex={0}
      aria-label={label}
      data-testid={testId}
    >
      <code>
        {lines.map((tokens, i) => (
          <span className="code__line" key={i}>
            {tokens.map((t, j) =>
              t.kind === 'text' ? t.text : (
                <span key={j} className={`tok tok--${t.kind}`}>
                  {t.text}
                </span>
              ),
            )}
            {i < lines.length - 1 ? '\n' : ''}
          </span>
        ))}
      </code>
    </pre>
  )
}
