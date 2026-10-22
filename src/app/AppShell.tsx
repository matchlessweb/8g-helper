import type { ReactNode } from 'react'
import { Logo } from '../brand/Logo'
import { LOGO } from '../brand/logoPaths'
import { ExternalLink } from '../components/ExternalLink'
import { LINKS, SECTIONS } from '../lib/links'
import { ThemeToggle } from '../theme/ThemeToggle'
import { MobileMenu } from './MobileMenu'
import './AppShell.css'

/** The bracket strokes of the logo, as closed outlines, so the wordmark can be drawn as one thin line all round. */
const BRACKET_OUTLINES = 'M0.5 4H9V7H3.5V33H9V36H0.5Z M40.632 4H49.132V36H40.632V33H46.132V7H40.632Z'

/** The giant outlined lockup at the foot of the page, cropped by the bottom edge (after scrollxui and kedhareswer on 21st.dev). */
function Wordmark() {
  return (
    <div className="wordmark" aria-hidden="true">
      <svg viewBox={`0 0 ${LOGO.width} ${LOGO.height}`} fill="none" strokeWidth="1">
        <path className="wordmark__brackets" d={BRACKET_OUTLINES} vectorEffect="non-scaling-stroke" />
        <path className="wordmark__letters" d={LOGO.sevenG} vectorEffect="non-scaling-stroke" />
        <path className="wordmark__letters" d={LOGO.helper} vectorEffect="non-scaling-stroke" />
      </svg>
    </div>
  )
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell" data-testid="app-shell">
      <a className="skip" href="#tool">
        Skip to the tool
      </a>
      <header className="masthead">
        <div className="masthead__inner">
          <a className="masthead__brand" href="/" aria-label="7G Helper, home">
            <Logo height={28} />
          </a>
          <nav className="masthead__nav" aria-label="Sections">
            {SECTIONS.map((s) => (
              <a key={s.href} href={s.href}>
                {s.label}
              </a>
            ))}
          </nav>
          <ThemeToggle />
          <MobileMenu />
        </div>
      </header>

      <main className="app-shell__main">{children}</main>

      <footer className="site-footer">
        <div className="site-footer__panel">
          <span className="site-footer__tint" aria-hidden="true" />
          <div className="site-footer__inner">
            <div className="site-footer__brand">
              <Logo height={28} />
              <p>Paste a 7G log line, see the rule that blocked it, and get an exception scoped to that one request.</p>
              <p className="site-footer__note">
                An independent tool, not affiliated with GridPane or the author of 7G. Review each exception file before
                using it on your own server.
              </p>
            </div>
            <nav className="site-footer__cols" aria-label="Footer">
              <div>
                <h2>The firewall</h2>
                <ul>
                  <li>
                    <ExternalLink href={LINKS.sevenG}>7G Firewall by Jeff Starr</ExternalLink>
                  </li>
                  <li>
                    <ExternalLink href={LINKS.gridpaneDocs}>GridPane’s 7G guide</ExternalLink>
                  </li>
                </ul>
              </div>
              <div>
                <h2>This tool</h2>
                <ul>
                  <li>
                    <a href="#tool">Paste a log line</a>
                  </li>
                  {SECTIONS.map((s) => (
                    <li key={s.href}>
                      <a href={s.href}>{s.label}</a>
                    </li>
                  ))}
                  <li>
                    <ExternalLink href={LINKS.source}>Source code on GitHub</ExternalLink>
                  </li>
                </ul>
              </div>
            </nav>
          </div>
          <div className="site-footer__bar">
            <p className="site-footer__credit">
              © 2026 7G Helper by <ExternalLink href={LINKS.jon}>Jon Phillips</ExternalLink> at{' '}
              <ExternalLink href={LINKS.matchless}>Matchless Web</ExternalLink>
            </p>
            <ul aria-label="Related sites">
              <li>
                <ExternalLink href={LINKS.gridpane}>GridPane</ExternalLink>
              </li>
              <li>
                <ExternalLink href={LINKS.perishable}>Perishable Press</ExternalLink>
              </li>
            </ul>
          </div>
          <Wordmark />
        </div>
      </footer>
    </div>
  )
}
