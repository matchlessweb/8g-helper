import { useCallback, useMemo, useSyncExternalStore, type ReactNode } from 'react'
import { ThemeContext } from './ThemeContext'
import { applyTheme, isTheme, THEME_STORAGE_KEY, type Theme } from './theme'

// The inline script in index.html sets <html data-theme> before the page paints; this reads it from there. The
// prerendered HTML is always rendered as light, so the server snapshot is 'light' and React swaps after hydrating.
const listeners = new Set<() => void>()
const subscribe = (fn: () => void) => {
  listeners.add(fn)
  return () => listeners.delete(fn)
}
const current = (): Theme => {
  const t = document.documentElement.dataset.theme ?? null
  return isTheme(t) ? t : 'light'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useSyncExternalStore(subscribe, current, () => 'light' as Theme)

  const setTheme = useCallback((next: Theme) => {
    applyTheme(next)
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next)
    } catch {
      // private window or blocked storage: the choice lasts for this page only
    }
    listeners.forEach((fn) => fn())
  }, [])

  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
