// Renders the page to HTML at build time (scripts/prerender.mjs), so the first paint and crawlers get real content.
import { StrictMode } from 'react'
import { renderToString } from 'react-dom/server'
import App from './App.tsx'

export function render(): string {
  return renderToString(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}
