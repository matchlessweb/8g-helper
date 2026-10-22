import { expect, test, type Page } from '@playwright/test'

const CLAUDEBOT =
  '2026-10-22T19:26:57+00:00 200 "GET /sitemap_index.xml" cookie=0 method=0 referer=0 bot=7 querystring=0 request=0 ip=203.0.113.10 ua="Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)" ref="-"'
const MOZLILA =
  '2026-10-22T15:16:27+00:00 404 "GET //cache/cache/cache.php" cookie=0 method=0 referer=0 bot=10 querystring=0 request=42 ip=203.0.113.10 ua="Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36" ref="-"'
const ACCESS_LOG =
  '203.0.113.20 - - [21/Oct/2026:14:02:11 +0000] "GET /pricing/ HTTP/2.0" 200 5120 "-" "Mozilla/5.0 (compatible; AhrefsSiteAudit/6.1; +http://ahrefs.com/robot/site-audit)"'
const SITES = ['/var/www/example.com/nginx/8g/8g-firewall.conf', '/var/www/example.org/nginx/8g/8g-firewall.conf']

/** Load the page and wait until React has attached, so a click on a cold load is never lost. */
async function open(page: Page) {
  await page.goto('/')
  await page.locator('html[data-ready]').waitFor({ state: 'attached' })
}

function watchConsole(page: Page): string[] {
  const problems: string[] = []
  page.on('console', (m) => (m.type() === 'error' || m.type() === 'warning') && problems.push(`${m.type()}: ${m.text()}`))
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
  return problems
}

async function paste(page: Page, text: string) {
  await page.getByTestId('log-input').fill(text)
  await page.getByTestId('log-submit').click()
}

/** What the read-only listing prints on a server where every copy has the rule on the given line, as 8G ships it. */
async function listing(page: Page, line: number, files = SITES): Promise<string> {
  const rule = (await page.locator('.diff__del').first().textContent())!.replace(/^- /, '')
  return files.map((f) => `${f}:${line}:\t${rule}`).join('\n')
}

test('the prerendered page names the tool and says it is independent', async ({ page }) => {
  const problems = watchConsole(page)
  const res = await page.goto('/')
  await page.locator('html[data-ready]').waitFor({ state: 'attached' })
  const html = await res!.text()
  expect(html.match(/<h1>(.*?)<\/h1>/)![1].replace(/<[^>]+>/g, '')).toBe('8G Firewall Rule Finder')
  expect(html).toContain('not affiliated with GridPane')
  await expect(page).toHaveTitle('8G Firewall Rule Finder | 8G Helper')
  const toggle = page.getByRole('button', { name: /Switch to (dark|light) theme/ })
  const before = await page.evaluate(() => document.documentElement.dataset.theme)
  await toggle.click()
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).not.toBe(before)
  for (const href of [
    'https://perishablepress.com/8g-firewall/',
    'https://github.com/t18d/nG-SetEnvIf',
    'https://jonphillips.dev/',
    'https://matchlessweb.com/',
  ]) {
    await expect(page.locator(`footer a[href="${href}"]`)).toHaveCount(1)
  }
  const source = page.locator('footer a[href="https://github.com/matchlessweb/8g-helper"]')
  await expect(source).toHaveCount(1)
  await expect(source).toHaveAttribute('target', '_blank')
  await expect(source).toContainText('GPL-3.0')
  expect(problems).toEqual([])
})

test('the example: see the rule, list the copies, get the edit', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const problems = watchConsole(page)
  await open(page)
  await page.getByRole('button', { name: 'Try an example' }).click()

  await expect(page.getByTestId('mode')).toHaveText('watch mode: logged only')
  const rules = page.getByTestId('rule-result')
  await expect(rules).toHaveCount(1)
  await expect(rules).toContainText('querystring 39')
  await expect(rules.locator('mark')).toHaveText('+get+')
  await expect(page.getByRole('heading', { name: 'Likely a false positive', exact: true })).toBeVisible()

  const fix = page.getByTestId('allow-fix')
  await expect(fix.locator('.edits__what')).toHaveText('querystring 39 take out get')
  await expect(fix).toContainText('grep -HnF')
  await expect(fix.getByText('The command appears here once the list is pasted above.')).toBeVisible()

  await page.getByTestId('copies-input').fill(await listing(page, 54))
  await expect(page.getByTestId('copies')).toContainText('2 copies')
  const edit = page.getByLabel('Commands: edit every copy')
  await expect(edit).toContainText(`set -- '${SITES[0]}' '${SITES[1]}'`)
  await expect(edit).toContainText('b=.bak-8g-helper-')
  await expect(edit).toContainText('if [ "$ok" = 1 ] && nginx -t; then')

  await fix.getByRole('button', { name: 'Copy', exact: true }).first().click()
  await expect(fix.getByRole('button', { name: 'Copied' })).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(await edit.textContent())
  expect(problems).toEqual([])
})

test('a copy that differs stops the edit and says why', async ({ page }) => {
  await open(page)
  await page.getByRole('button', { name: 'Try an example' }).click()
  const good = await listing(page, 54, [SITES[0]])
  await page.getByTestId('copies-input').fill(`${good}\n${SITES[1]}:0:none of these rules`)
  await expect(page.getByRole('alert').filter({ hasText: SITES[1] })).toContainText('does not have querystring rule 39')
  await expect(page.getByLabel('Commands: edit every copy')).toHaveCount(0)
})

test('a crawler gets a policy verdict, not an attack', async ({ page }) => {
  await open(page)
  await paste(page, CLAUDEBOT)
  await expect(page.getByTestId('verdict')).toContainText('Crawler policy: Anthropic')
  await expect(page.getByRole('heading', { name: 'Allow this crawler for now', exact: true })).toBeVisible()
  await expect(page.getByTestId('allow-fix').locator('.edits__what')).toHaveText('bot 7 take out claudebot')
})

test('an attack probe keeps its fix folded away, and lists both groups', async ({ page }) => {
  await open(page)
  await paste(page, MOZLILA)
  await expect(page.getByRole('heading', { name: 'Leave it blocked', exact: true })).toBeVisible()
  await expect(page.getByTestId('rule-result')).toHaveCount(2)
  await expect(page.getByTestId('allow-fix')).toBeHidden()
  await page.getByText('Allow it anyway').click()
  await expect(page.getByTestId('allow-fix')).toBeVisible()
})

test('an access log line says what 8G would do', async ({ page }) => {
  await open(page)
  await paste(page, ACCESS_LOG)
  await expect(page.getByTestId('mode')).toHaveText('access log line')
  await expect(page.locator('.rules__lead')).toHaveText(
    'An access log line doesn’t say what 8G did. With 8G on, bot rule 3 would block this request.',
  )
})

test('text that is not a log line says so and shows no fix', async ({ page }) => {
  await open(page)
  await paste(page, 'this line holds no rule')
  await expect(page.getByTestId('no-rule-message')).toBeVisible()
  await expect(page.getByTestId('rule-result')).toHaveCount(0)
  await expect(page.getByTestId('allow-fix')).toHaveCount(0)
})

test('every link that leaves the site opens a new tab and shows the arrow', async ({ page }) => {
  await open(page)
  const links = await page.locator('a[href^="http"]').evaluateAll((as) =>
    as.map((a) => ({
      href: a.getAttribute('href'),
      target: a.getAttribute('target'),
      rel: a.getAttribute('rel') ?? '',
      arrow: a.querySelector('svg.extlink__icon') !== null,
    })),
  )
  expect(links.length).toBeGreaterThanOrEqual(8)
  for (const l of links) expect(l, l.href!).toEqual({ ...l, target: '_blank', rel: 'noopener noreferrer', arrow: true })
})

test('the phone menu opens, jumps to a section and closes', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 })
  await open(page)
  await expect(page.locator('.masthead__nav')).toBeHidden()
  const toggle = page.getByRole('button', { name: 'Open menu' })
  await expect(toggle).toHaveAttribute('aria-expanded', 'false')
  await toggle.click()
  const menu = page.locator('#mobile-menu')
  await expect(menu).toBeVisible()
  await expect(page.getByRole('button', { name: 'Close menu' })).toHaveAttribute('aria-expanded', 'true')
  await menu.getByRole('link', { name: 'Rule groups' }).click()
  await expect(menu).toHaveCount(0)
  await expect(page).toHaveURL(/#rules$/)
  await page.getByRole('button', { name: 'Open menu' }).click()
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Open menu' })).toBeFocused()
})
