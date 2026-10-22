import { CornerDownRight, FileCode2, MessageSquareText } from 'lucide-react'
import { CodeLines } from './CodeLines'

const FILE = `if ($bad_request_7g = $allow7g_rankmath_15) {
    set $7g_drop_bad_request 0;
}`

/** The mechanism in one picture: a log line, the part 7G matched, the rule named beside it, the file it gives. Plays once. */
export function HeroDemo() {
  return (
    <figure className="demo" aria-label="Example: a 7G log line, the rule that blocked it, and the exception file">
      <div className="window">
        <div className="window__bar">
          <span className="window__tab mono">7g.log</span>
          <span className="window__meta mono">example.com</span>
        </div>
        <p className="demo__line mono">
          <span className="demo__dim">[21/Oct/2026:06:25:38 +0000] </span>
          <span className="demo__rule">[":bad_request_15:"]</span>
          <span className="demo__dim"> 203.0.113.20 example.com </span>
          "GET /wp-json/rankmath/v1/getHead?url=<mark className="demo__hit">https://</mark>example.com HTTP/2.0" 403
        </p>
      </div>

      <div className="demo__note">
        <CornerDownRight className="demo__elbow" aria-hidden="true" />
        <div className="note">
          <p className="note__head">
            <MessageSquareText aria-hidden="true" />
            <code>bad_request_15</code>
            <span>Request URI rules</span>
          </p>
          <p className="note__body">
            Matched <code>https://</code> in the address. Rank Math’s SEO preview sends your own URL here:{' '}
            <strong>likely a false positive.</strong>
          </p>
        </div>
      </div>

      <div className="window demo__file">
        <div className="window__bar">
          <span className="window__tab mono">
            <FileCode2 aria-hidden="true" />
            allow-rankmath-7g-context.conf
          </span>
        </div>
        <CodeLines code={FILE} language="nginx" numbered wrap />
      </div>
    </figure>
  )
}
