import { expect, test, type Page } from '@playwright/test'

const RANK_MATH =
  '[21/Oct/2026:06:25:38 +0000] [":bad_request_15:"] 203.0.113.20 example.org "GET /wp-json/rankmath/v1/getHead?url=https://example.org HTTP/2.0" 403 0.000 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"'
const FACEBOOK =
  '[21/Oct/2026:00:30:40 +0000] [":bad_bot_6:"] 2001:db8:11ff:4d:: example.org "GET /robots.txt HTTP/2.0" 403 0.000 "-" "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"'
const ENV_PROBE =
  '[21/Oct/2026:11:40:47 +0000] [":bad_request_27:"] 203.0.113.10 shop.example.com "GET /.env HTTP/2.0" 403 0.000 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"'

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

test('the prerendered page names the tool and says it is independent', async ({ page }) => {
  const problems = watchConsole(page)
  const res = await page.goto('/')
  await page.locator('html[data-ready]').waitFor({ state: 'attached' })
  const html = await res!.text()
  expect(html.match(/<h1>(.*?)<\/h1>/)![1].replace(/<[^>]+>/g, '')).toBe('7G Firewall Exception Generator')
  expect(html).toContain('not affiliated with GridPane')
  await expect(page).toHaveTitle('7G Firewall Exception Generator | 7G Helper')
  const toggle = page.getByRole('button', { name: /Switch to (dark|light) theme/ })
  const before = await page.evaluate(() => document.documentElement.dataset.theme)
  await toggle.click()
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).not.toBe(before)
  await expect(page.locator('footer a[href="https://gridpane.com/"]')).toHaveCount(1)
  await expect(page.locator('footer a[href="https://perishablepress.com/"]')).toHaveCount(1)
  await expect(page.locator('footer a[href="https://jonphillips.dev/"]')).toHaveCount(1)
  await expect(page.locator('footer a[href="https://matchlessweb.com/"]')).toHaveCount(1)
  const source = page.locator('footer a[href="https://github.com/matchlessweb/7g-helper"]')
  await expect(source).toHaveCount(1)
  await expect(source).toHaveAttribute('target', '_blank')
  expect(problems).toEqual([])
})

test('paste a line, see the rule, copy the file', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const problems = watchConsole(page)
  await open(page)
  await page.getByTestId('log-input').fill(RANK_MATH)
  await page.getByTestId('log-submit').click()

  const rules = page.getByTestId('rule-result')
  await expect(rules).toHaveCount(1)
  await expect(rules).toContainText('bad_request_15')
  await expect(rules.locator('mark')).toHaveText('https://')
  await expect(page.getByRole('heading', { name: 'Likely a false positive', exact: true })).toBeVisible()

  const file = page.getByTestId('exception-file')
  await expect(file).toContainText('set $7g_drop_bad_request 0;')
  await expect(file).toContainText('if ($bad_request_7g = $allow7g_rankmath_v1_gethead_bad_request_15)')
  await expect(page.getByTestId('exception-path')).toHaveText(
    '/var/www/example.org/nginx/allow-rankmath-v1-gethead-7g-context.conf',
  )

  await page.getByRole('button', { name: 'Copy file' }).click()
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`${await file.textContent()}\n`)

  await page.getByLabel('Every site on this server').check()
  await expect(page.getByTestId('exception-path')).toHaveText('/etc/nginx/extra.d/allow-rankmath-v1-gethead-7g-context.conf')
  expect(problems).toEqual([])
})

test('an attack probe keeps its file folded away', async ({ page }) => {
  await open(page)
  await page.getByTestId('log-input').fill(ENV_PROBE)
  await page.getByTestId('log-submit').click()
  await expect(page.getByRole('heading', { name: 'Leave it blocked', exact: true })).toBeVisible()
  await expect(page.getByTestId('exception-file')).toBeHidden()
  await page.getByText('Write an exception anyway').click()
  await expect(page.getByTestId('exception-file')).toBeVisible()
})

test('text with no 7G rule says so and shows no file', async ({ page }) => {
  await open(page)
  await page.getByTestId('log-input').fill('this line holds no rule')
  await page.getByTestId('log-submit').click()
  await expect(page.getByTestId('no-rule-message')).toBeVisible()
  await expect(page.getByTestId('rule-result')).toHaveCount(0)
  await expect(page.getByTestId('exception-file')).toHaveCount(0)
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

test('a custom-list rule offers to take the crawler off the list, and the exception as the alternative', async ({ page }) => {
  const problems = watchConsole(page)
  await open(page)
  await page.getByTestId('log-input').fill(FACEBOOK)
  await page.getByTestId('log-submit').click()

  await expect(page.getByTestId('rule-result')).toContainText(
    "grep -HnE '[[:space:]]6;[[:space:]]*$' /etc/nginx/extra.d/*7g-bad-bot-context.conf",
  )
  await expect(page.getByRole('heading', { name: 'Take it off your list', exact: true })).toBeVisible()
  const fix = page.getByTestId('list-fix')
  await expect(fix).toContainText('s/\\|facebookexternalhit\\)/)/I')
  await expect(fix).toContainText('/root/$(basename "$f").bak-')
  await expect(page.getByRole('heading', { name: 'Or keep the list: the exception file', exact: true })).toBeVisible()
  await expect(page.getByTestId('exception-file')).toContainText('if ($bad_bot_7g = $allow7g_facebook_bad_bot_6)')
  expect(problems).toEqual([])
})
