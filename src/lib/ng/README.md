# 8G rules and matching (`src/lib/ng/`)

This module reads one nginx log line and says which 8G rule fired, the exact pattern, and the text that matched.
It covers nG-SetEnvIf's 8G FIREWALL v1.5 (`rules/8g-firewall.conf`, commit `344d9c4`, GPL-3.0; see
`LICENSE`). It is pure TypeScript, with no DOM and no dependencies.

## Use

```ts
import { GROUPS } from './ng/ruleset.ts'       // the parsed rules (Vite ?raw import)
import { analyze } from './ng/analyze.ts'
import { planAllow, findCopiesCommand, parseCopies, buildAllowCommands } from './ng/allowfix.ts'

const results = analyze(pastedText, GROUPS)     // one LineResult per non-empty, non-# line
```

In Node (tests, scripts), use `parseFirewall(readFileSync('rules/8g-firewall.conf', 'utf8'))` in place of `GROUPS`.

## Exports

| File | Exports |
| --- | --- |
| `rules.ts` | `parseFirewall(text) → Map<GroupId, RuleGroup>` (in check order; throws on any line it does not understand). It also exports `RULESET_SOURCE`, `CHECK_ORDER`, `FIELD_TO_GROUP`, `ruleName(group, n)`, `nginxUnquote` and `nginxUnquoteMapped`, plus the types `GroupId`, `FieldName`, `InputName`, `Rule {group, number, line, sourceLine, source, pattern, regex, differences}` and `RuleGroup {id, field, variable, input, order, status: 403 \| 405, line, rules}`. |
| `pcre.ts` | `compilePcre(pattern) → RegExp`, `parsePcre`, `removals`, `isNameLike`, `hasEmptyAlternative`, and the type `PcreDifference`. |
| `uri.ts` | `normalizeUri(path, mergeSlashes = true) → {ok, uri} \| {ok: false, problem, reason}` and `splitRequestUri(requestUri) → {path, queryString, hasQuery}`. |
| `logline.ts` | `parseLogLine(raw) → {ok, line: LogLine} \| {ok: false, raw, reason}`, `splitLines`, `unescapeLog`, `toBytes`, `printable` (show a byte string with `\xHH` for odd bytes) and `cutSpans`. |
| `match.ts` | `matchLine(line, groups) → GroupResult[]` (all six groups), `matchGroup(group, value) → RuleMatch[]`, `matchOutsideCuts` and `inputValue`. |
| `analyze.ts` | `analyze(text, groups) → LineResult[]`, `analyzeLine(raw, groups) → LineResult`, and the types `Mode` and `Fired`. |
| `verdict.ts` | `judge(line, groups) → Verdict {kind, title, reason, crawler?}`, `VERDICT_TITLE` and `knownCrawler(ua)`. |
| `allowfix.ts` | `planAllow(groupResult, allGroups) → AllowPlan \| undefined`, `editsFor`, `findCopiesCommand(edits)`, `parseCopies(output, edits) → {copies, problems, notes}`, `buildAllowCommands(edits, copies, 'YYYY-MM-DD') → {edit, verify, restore, backupSuffix}`, `sedExpression`, `ruleText`, `shellQuote` and `RELOAD`. |

### What a successful line gives you

A successful `LineResult` (`{ok: true}`) has these fields:

- **`line: LogLine`**
  - `format`: `'ng8'` (our 8G log line), `'ng_reason'` (a line carrying `:bad_bot_3:` tokens) or `'combined'` (an access log line).
  - `time`, `status`, `ip`, `method`, `requestUri`, `path`, `queryString` (raw), `uri` (nginx's decoded `$uri`), `uriProblem`, `protocol`.
  - `userAgent` and `referer`: `''` means the header was absent (`-`); `undefined` means the line does not say.
  - `logged` (number per group), and `cut` (the line was shortened before it was pasted).
- **`groups: GroupResult[]`**: six entries, each with:
  - `group`;
  - `value`: what the map read;
  - `matches: RuleMatch[]`: every rule that matches, in file order. Each match has `{rule, matched: {text, index}, first, inCut}`. `first` marks the one nginx returns;
  - `logged`;
  - `loggedRule`;
  - `check {status: 'confirmed' | 'unchecked' | 'mismatch', reason, note}`.
- **`fired?: Fired`**: `{group, number, rule?, from: 'log' | 'match'}`. This is the first group in check order that fired.
- **`mode`**: `'enforce'`, `'watch'` or `'unknown'`.
- **`nothing?`** (why nothing fired) and **`verdict?`**.

All values are byte strings, one character per byte. Show them with `printable()`.

## Semantics decisions

- **Check order.** The order is cookie, method, referer, bot, querystring, request, as in `8g.conf`. The first group that is not 0 is the one that blocks: 403, or 405 for the method rule. Inside a map, nginx returns only the first matching regex, in file order. So every match is listed, and the first one is marked.
- **Mode.** On an 8G log line, the mode is `enforce` when the status equals the fired group's status (403/405). Otherwise it is `watch`: 8G only logged, and something else answered, for example a 444 from GridPane's own XML-RPC block. One caveat: in watch mode, a 403 from WordPress or 7G reads as enforce. A `$ng_reason` line always means enforce. An access log line gives `unknown`.
- **PCRE vs JavaScript.** Every one of the 118 patterns compiles with flag `i`. Patterns are translated where PCRE differs:
  - `.` becomes `[^\n]`, because PCRE's dot matches CR (24 rules);
  - `$` also matches before one final LF (14 rules);
  - `\s` excludes 0xA0, because JavaScript's `\s` matches it (5 rules).

  `parsePcre` refuses any construct it cannot translate, so a new 8G release fails loudly instead of silently.
- **`$uri` and `$query_string`.** `$uri` is decoded once. Slashes are merged (nginx's default: `merge_slashes on`). `.` and `..` segments are resolved, including `%2e%2e`, and `%2f` is merged too. `%25`, `%23` and `%3f` stay as literal `%`, `#` and `?`. `%00`, a bad escape, and climbing above the root give a 400 before any map runs. `$query_string` is raw. It stops at a `#`, and a `#` before the `?` leaves no query string. Both were checked against nginx 1.27.5 and 1.30.6 with `bash test/nginx/run.sh`.
  - **Consequences of the decoding.** Request rule 18's `%7e` can only match a request that sent `%257e`. Request rule 14's `///` cannot match with merge_slashes on.
- **Log escaping.** nginx writes `"`, `\` and bytes outside 0x20–0x7e as `\xHH`, and Apache writes `\"` and `\\`. Both are undone. Pasted non-ASCII text is UTF-8 encoded.
- **Cookies** are never in the line. The cookie group is `unchecked`, and its plan comments out the logged rule.
- **Shortened lines** (`abcd...` or `…`, as the WAF report masks values). A match that overlaps or touches the cut is `inCut`, is never `first`, and is set aside in the note. A logged rule that may depend on the cut is `unchecked` (reason `cut`), never a mismatch. A cut in the path also hides the query string.
- **Verdicts.** 8G's bot rules are a crawler policy, not attack signatures. A named crawler gets `crawler` (with a name) and the copy explains the choice. Fake browsers and scanner tools get `attack`. Known false positives get `false_positive`: a site search with `s=` and no SQL in it, an OAuth `redirect_uri` to localhost, and request rule 28 or 30 on a page the site served. XML-RPC and the cookie rule are `judgment`.
- **Allow it for now.** The plan uses the fewest name-like alternatives to take out so that no rule in the group matches the request. When a rule is not a list of names, it is commented out whole. Two matching rules are both edited, for example Stripe's `scan` in bot rules 3 and 11. The plan never leaves `(?:)` or a dangling `|`. Its warnings come back as data (`AllowWarningCode`): `server_wide`, `update`, `token_everywhere`, `rule_off`, `other_rules`, `other_groups`, `whole_rule` and `shortened`. The commands work in three steps:
  1. A read-only `grep -HnF` lists every copy (`nginx -T` includes, plus `/var/www/*/nginx/8g/8g-firewall.conf`).
  2. You paste that listing back. The edit then names each file and line, and refuses to run if backups already exist. It writes a `.bak-8g-helper-<date>` per file, makes one exact sed per line, checks each line, then runs `nginx -t && gp ngx reload`. If anything fails, it puts every backup back.
  3. It runs in a `( … )` subshell, so a STOP never closes the SSH session.

  `test/unit/ng-allowfix.test.ts` proves this with GNU sed on ubuntu:24.04, against a fake two-site server and every possible edit. It also proves it in nginx:1.27 (`nginx -t`, plus a request that now gets 0).
