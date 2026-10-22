import { ArrowDown } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { SECTIONS } from '../lib/links'

/** Hamburger that folds into an X (after efferd's Menu Toggle Icon on 21st.dev). */
function MenuIcon({ open }: { open: boolean }) {
  return (
    <svg
      className="menu-icon"
      data-open={open}
      viewBox="0 0 32 32"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path
        className="menu-icon__fold"
        d="M27 10 13 10C10.8 10 9 8.2 9 6 9 3.5 10.8 2 13 2 15.2 2 17 3.8 17 6L17 26C17 28.2 18.8 30 21 30 23.2 30 25 28.2 25 26 25 23.8 23.2 22 21 22L7 22"
      />
      <path d="M7 16 27 16" />
    </svg>
  )
}

/**
 * The phone menu: a dropdown under the masthead. It is mounted only while open, so nothing parked off screen can
 * widen the page, and it closes on a link, Escape, a tap outside, or the window growing past the phone layout.
 */
export function MobileMenu() {
  const [open, setOpen] = useState(false)
  const wrap = useRef<HTMLDivElement>(null)
  const button = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      setOpen(false)
      button.current?.focus()
    }
    const onPointer = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false)
    }
    const wide = window.matchMedia('(min-width: 641px)')
    const onWide = () => wide.matches && setOpen(false)
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointer)
    wide.addEventListener('change', onWide)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointer)
      wide.removeEventListener('change', onWide)
    }
  }, [open])

  return (
    <div className="mobile-menu-wrap" ref={wrap}>
      <button
        ref={button}
        type="button"
        className="iconbtn menu-toggle"
        aria-expanded={open}
        aria-controls="mobile-menu"
        aria-label={open ? 'Close menu' : 'Open menu'}
        onClick={() => setOpen((o) => !o)}
      >
        <MenuIcon open={open} />
      </button>
      {open && (
        <nav id="mobile-menu" className="mobile-menu" aria-label="Sections">
          <ol>
            {SECTIONS.map((s, i) => (
              <li key={s.href} style={{ animationDelay: `${i * 40}ms` }}>
                <a href={s.href} onClick={() => setOpen(false)}>
                  <span className="mobile-menu__num mono" aria-hidden="true">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  {s.label}
                </a>
              </li>
            ))}
          </ol>
          <a className="button button--primary mobile-menu__cta" href="#tool" onClick={() => setOpen(false)}>
            Paste a log line
            <ArrowDown aria-hidden="true" />
          </a>
        </nav>
      )}
    </div>
  )
}
