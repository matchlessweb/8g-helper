# 8G Helper

**[8ghelper.com](https://8ghelper.com/)** (not live yet): a free tool that reads an 8G firewall log line and names the
rule that fired.

Paste a line from a site's 8G log, or from any nginx or Apache access log. 8G Helper shows which 8G rule matched, its
exact pattern, the text in the request that set it off, and any other rule in the same group that matches too. For a
request you want, it gives nG's documented way to let it through for now, and what that costs. The page also explains
how to run 8G beside 7G on GridPane in watch mode before switching over.

Everything runs in the browser. There is no server, no account, and nothing you paste leaves the page.

## Status

Not live yet; it goes up at 8ghelper.com on Cloudflare Pages. Started 2026-10-22 from
[7G Helper](https://github.com/matchlessweb/7g-helper) v1. It covers 8G on nginx (nG-SetEnvIf). Apache 8G comes next,
tested against real Apache before it ships. Scoped per-site exceptions wait until enforce mode has been tested on a
staging site.

## How it works

- `rules/8g-firewall.conf` and `rules/8g.conf` are nG-SetEnvIf's files, unchanged, pinned to one commit of 8G v1.5.
- `src/lib/ng/` parses those maps, reads the three kinds of log line, matches each part of the request the way nginx
  does (the query string raw, the path decoded), and writes the interim fix. Its own README lists the API.
- `src/content/runbook.ts` holds the GridPane commands, copied by `scripts/import-runbook.mjs` from the tested runbook in
  the 8G for GridPane repo, so the page shows exactly what was run.

## Run it locally

Requires Node 22 (see `.nvmrc`).

```bash
npm ci
npm run dev          # http://127.0.0.1:5173
npm run build        # type-check, build, prerender into dist/
npm test             # unit tests
npm run test:e2e     # Playwright smoke tests against the built page
```

## Credits

- **8G Firewall** by Jeff Starr: [perishablepress.com/8g-firewall](https://perishablepress.com/8g-firewall/).
- **nG-SetEnvIf** by Tonkünstler-on-the-Bund, the nginx version of 8G:
  [github.com/t18d/nG-SetEnvIf](https://github.com/t18d/nG-SetEnvIf), GPL-3.0. The files in `rules/` are theirs,
  unchanged, headers included.

8G Helper is an independent tool, not affiliated with GridPane, the author of 8G, or the author of nG-SetEnvIf. Check
every change before you make it on your own server.

## License

GPL-3.0, the same license as nG-SetEnvIf, whose rules the page bundles and runs. See `LICENSE`.

Copyright (C) 2026 Matchless Web Studio LLC. 8G Helper is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License, version 3, as published by the Free Software Foundation. It comes
with no warranty.

Built by [Jon Phillips](https://jonphillips.dev/) at [Matchless Web](https://matchlessweb.com/).
