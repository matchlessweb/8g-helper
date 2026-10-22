# 7G Helper

**[7ghelper.com](https://7ghelper.com/)**: a free 7G firewall exception generator for GridPane.

Paste a line from a site's 7G log (`/var/www/<site>/logs/7g.log`). 7G Helper shows which rule blocked the request and
what part of it set the rule off, then writes an nginx exception file that lets that one kind of request through and
keeps every other rule on. It also gives the commands to check the config, reload nginx, and prove the fix: one test
request that should now pass, and one that should still get a 403.

Everything runs in the browser. There is no server, no account, and nothing you paste leaves the page.

## How it works

- `src/lib/logline.ts` reads a GridPane 7G log line into its parts: the rule that fired, the address, the user agent,
  the referrer and the method.
- `src/lib/ruleset.ts` and `src/lib/rules.ts` load GridPane's 7G maps from `rules/gridpane-7g-mappings.conf`, the file
  GridPane ships, and `src/lib/match.ts` finds the pattern and the exact text that matched.
- `src/lib/exception.ts` writes the exception in GridPane's update-safe form (`*-7g-context.conf`), scoped so it lifts
  the block only when the named rule is the one that fired.
- `src/lib/listfix.ts` handles rules that come from a custom list on the server (not GridPane's own), offering to take
  one name off the list instead.

## Run it locally

Requires Node 22 (see `.nvmrc`).

```bash
npm ci
npm run dev          # http://127.0.0.1:5173
npm run build        # type-check, build, prerender into dist/
npm test             # unit tests, on real (anonymized) 7G log lines
npm run test:e2e     # Playwright smoke tests against the built page
```

The site is a static build (React and TypeScript on Vite, prerendered) hosted on Cloudflare Pages.

## Credits

- **7G Firewall** by Jeff Starr: [perishablepress.com/7g-firewall](https://perishablepress.com/7g-firewall/). 7G is free
  to use with its credit lines kept, and they are kept in the rule files here.
- **GridPane's 7G** (the nginx version GridPane ships):
  [GridPane's 7G guide](https://gridpane.com/kb/using-the-7g-web-application-firewall/). The files in `rules/` are
  copied from a GridPane server and keep their original headers.

7G Helper is an independent tool, not affiliated with GridPane or the author of 7G. Review every exception file before
you use it on your own server.

## License

The code in this repository is released under the [MIT License](LICENSE), © 2026 Matchless Web Studio LLC. The files in
`rules/` are third-party configuration reproduced with their credits; the MIT License does not change their terms.

Built by [Jon Phillips](https://jonphillips.dev/) at [Matchless Web](https://matchlessweb.com/).
