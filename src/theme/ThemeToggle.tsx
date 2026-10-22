import { useTheme } from './useTheme'

// The house toggle (matchlessweb.com): one half-filled circle that turns 180 degrees between themes.
export function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const next = theme === 'light' ? 'dark' : 'light'

  function toggle() {
    const root = document.documentElement
    root.classList.add('theme-fade')
    setTheme(next)
    window.setTimeout(() => root.classList.remove('theme-fade'), 220)
  }

  return (
    <button type="button" className="iconbtn theme-toggle" onClick={toggle} aria-label={`Switch to ${next} theme`}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden="true">
        <circle cx="12" cy="12" r="8.25" />
        <path d="M12 3.75a8.25 8.25 0 0 1 0 16.5z" fill="currentColor" stroke="none" />
      </svg>
    </button>
  )
}
