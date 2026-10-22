export type Theme = 'light' | 'dark'

export const THEMES: readonly Theme[] = ['light', 'dark']

export const THEME_STORAGE_KEY = '8g-helper-theme'

export function isTheme(value: string | null): value is Theme {
  return value === 'light' || value === 'dark'
}

export function systemTheme(): Theme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'light'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function readStoredTheme(): Theme | null {
  if (typeof window === 'undefined') return null
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
  return isTheme(stored) ? stored : null
}

export function applyTheme(theme: Theme) {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = theme
}
