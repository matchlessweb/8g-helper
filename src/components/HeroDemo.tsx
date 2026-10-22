import { CornerDownRight, FileCode2, MessageSquareText } from 'lucide-react'
import { CodeLines } from './CodeLines'

const RULE = `map $http_user_agent $bad_bot_ng {
    "~*ahrefs|archiver|curl|libwww-perl|pycurl|scan" 3;
}`

/** The mechanism in one picture: a log line, the part 8G matched, the rule named beside it, the pattern behind it. */
export function HeroDemo() {
  return (
    <figure className="demo" aria-label="Example: an 8G log line, the rule that fired, and its pattern">
      <div className="window">
        <div className="window__bar">
          <span className="window__tab mono">8g.log</span>
          <span className="window__meta mono">example.com</span>
        </div>
        <p className="demo__line mono">
          <span className="demo__dim">2026-10-21T14:02:11+00:00 200 </span>
          "GET /pricing/"
          <span className="demo__dim"> cookie=0 method=0 referer=0 </span>
          <span className="demo__rule">bot=3</span>
          <span className="demo__dim"> querystring=0 request=0 ip=203.0.113.20 </span>
          ua="Mozilla/5.0 (compatible; <mark className="demo__hit">Ahrefs</mark>SiteAudit/6.1;
          +http://ahrefs.com/robot/site-audit)"
        </p>
      </div>

      <div className="demo__note">
        <CornerDownRight className="demo__elbow" aria-hidden="true" />
        <div className="note">
          <p className="note__head">
            <MessageSquareText aria-hidden="true" />
            <code>bot 3</code>
            <span>User agent rules</span>
          </p>
          <p className="note__body">
            Matched <code>Ahrefs</code> in the user agent. Ahrefs Site Audit checks your site for SEO problems:{' '}
            <strong>likely one you want.</strong>
          </p>
        </div>
      </div>

      <div className="window demo__file">
        <div className="window__bar">
          <span className="window__tab mono">
            <FileCode2 aria-hidden="true" />
            8g-firewall.conf
          </span>
          <span className="window__meta mono">line 130</span>
        </div>
        <CodeLines code={RULE} language="nginx" wrap />
      </div>
    </figure>
  )
}
