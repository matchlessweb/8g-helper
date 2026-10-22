// Writes the server-rendered page into dist/index.html, in place of the empty root. Runs after both vite builds.
// It also inlines the one stylesheet, so the first paint waits on no second request, and preloads the fonts the
// first screen sets: in the page, and as a Link header on / that Cloudflare sends as 103 Early Hints when the zone's
// Early Hints setting is on.
import { appendFile, readdir, readFile, rm, writeFile } from 'node:fs/promises'

const dist = new URL('../dist/', import.meta.url)
const ssr = new URL('../dist-ssr/', import.meta.url)
const { render } = await import(new URL('entry-server.js', ssr).href)

let page = await readFile(new URL('index.html', dist), 'utf8')

const sheet = page.match(/<link rel="stylesheet" crossorigin href="\/assets\/(index-[\w-]+\.css)">/)
if (!sheet) throw new Error('dist/index.html links no stylesheet to inline')
const cssFile = new URL(`assets/${sheet[1]}`, dist)
const css = await readFile(cssFile, 'utf8')
if (css.includes('</style')) throw new Error('the stylesheet cannot be inlined as it stands')
await rm(cssFile)

// Body text (the lead), the hero heading, the nav and buttons, and the mono status line above the heading.
const FIRST_SCREEN = [
  'ibm-plex-sans-latin-400-normal',
  'ibm-plex-sans-latin-700-normal',
  'ibm-plex-sans-latin-500-normal',
  'ibm-plex-mono-latin-500-normal',
]
const assets = await readdir(new URL('assets/', dist))
const fonts = FIRST_SCREEN.map((name) => {
  const file = assets.find((a) => a.startsWith(`${name}-`) && a.endsWith('.woff2'))
  if (!file || !css.includes(`/assets/${file}`)) throw new Error(`no built woff2 the stylesheet uses for ${name}`)
  return `/assets/${file}`
})
const preloads = fonts.map((href) => `<link rel="preload" href="${href}" as="font" type="font/woff2" crossorigin>`)
// A function, not a string: in a replacement string $& and $' are patterns, and the markup can contain them.
page = page.replace(sheet[0], () => `${preloads.join('\n    ')}\n    <style>${css}</style>`)
const link = fonts.map((href) => `<${href}>; rel=preload; as=font; type="font/woff2"; crossorigin`).join(', ')
await appendFile(new URL('_headers', dist), `\n# Written by scripts/prerender.mjs: the first-screen fonts, as Early Hints.\n/\n  Link: ${link}\n`)

const empty = '<div id="root"></div>'
if (!page.includes(empty)) throw new Error('dist/index.html has no empty root to fill')
const html = render()
if (!html.includes('<h1')) throw new Error('the prerendered page has no h1')
page = page.replace(empty, () => `<div id="root">${html}</div>`)
if (!page.includes(html) || !page.includes(css)) throw new Error('the written page lost markup on the way in')
await writeFile(new URL('index.html', dist), page)
await rm(ssr, { recursive: true })
console.log(`prerendered dist/index.html (${html.length} characters of markup)`)
