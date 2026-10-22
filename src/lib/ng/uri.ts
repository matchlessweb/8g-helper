// The two request variables 8G reads, rebuilt from the raw request target ($request_uri) the way nginx builds them.
//
// $query_string is everything after the first ?, raw: never percent-decoded, + stays +. It stops at a #, and a #
// before the first ? leaves no query string at all (checked against nginx 1.27).
// $uri is the path only, made by nginx's ngx_http_parse_complex_uri with merge_slashes on (nginx's default):
// - %XX is decoded once, and a decoded / or . then counts as a real one: %2f merges and %2e%2e climbs a level.
//   A decoded %, # or ? is kept as a plain character and not decoded again: %2541 gives %41, %3f gives ?.
// - // (and longer runs) become one /.
// - /./ is dropped and /x/../ goes up one level, also at the end (/a/. gives /a/, /a/.. gives /).
// - + stays + (only a query string uses + for a space, and nginx does not decode that either).
// - A # ends the path (a fragment; browsers and curl never send one).
// nginx answers 400 before any map runs for: a % not followed by two hex digits, %00, and .. above the root.
// Strings are byte strings: one character per byte (0-255), as nginx sees them.

export type UriProblem = 'bad_escape' | 'nul' | 'above_root' | 'not_a_path'

export type NormalizedUri = { ok: true; uri: string } | { ok: false; problem: UriProblem; reason: string }

export interface RequestTarget {
  /** The raw path, before the first ? or #. */
  path: string
  /** $query_string: raw, after the first ? and up to a #, '' when there is none. */
  queryString: string
  hasQuery: boolean
}

const REASONS: Record<UriProblem, string> = {
  bad_escape: 'a % in the address is not followed by two hex digits',
  nul: 'the address has %00 in its path',
  above_root: 'the address climbs above the top folder with ..',
  not_a_path: 'the address does not start with /',
}

export function splitRequestUri(requestUri: string): RequestTarget {
  const q = requestUri.indexOf('?')
  const h = requestUri.indexOf('#')
  if (q === -1 || (h !== -1 && h < q)) {
    return { path: requestUri.slice(0, h === -1 ? undefined : h), queryString: '', hasQuery: false }
  }
  const end = requestUri.indexOf('#', q)
  return { path: requestUri.slice(0, q), queryString: requestUri.slice(q + 1, end === -1 ? undefined : end), hasQuery: true }
}

const hex = (c: string | undefined): number => (c !== undefined && /^[0-9A-Fa-f]$/.test(c) ? parseInt(c, 16) : -1)

type State = 'usual' | 'slash' | 'dot' | 'dot_dot' | 'quoted' | 'quoted_second'

/** $uri from the raw path (the part of $request_uri before the first ?). */
export function normalizeUri(path: string, mergeSlashes = true): NormalizedUri {
  const bad = (problem: UriProblem): NormalizedUri => ({ ok: false, problem, reason: REASONS[problem] })
  if (!path.startsWith('/')) return bad('not_a_path')

  const u: string[] = []
  // nginx's "u -= 4", then back to the previous /: drops the segment before a "..".
  const up = (): boolean => {
    let k = u.length - 4
    for (;;) {
      if (k < 0) return false
      if (u[k] === '/') break
      k--
    }
    u.length = k + 1
    return true
  }

  let state: State = 'usual'
  let quotedState: State = 'usual'
  let decoded = 0
  let p = 0
  let ch: string | undefined = path[p++]

  while (ch !== undefined) {
    switch (state) {
      case 'usual':
        if (ch === '/') {
          state = 'slash'
          u.push(ch)
        } else if (ch === '%') {
          quotedState = state
          state = 'quoted'
        } else if (ch === '#') {
          return { ok: true, uri: u.join('') }
        } else {
          u.push(ch)
        }
        ch = path[p++]
        break

      case 'slash':
        if (ch === '/') {
          if (!mergeSlashes) u.push(ch)
        } else if (ch === '.') {
          state = 'dot'
          u.push(ch)
        } else if (ch === '%') {
          quotedState = state
          state = 'quoted'
        } else if (ch === '#') {
          return { ok: true, uri: u.join('') }
        } else {
          state = 'usual'
          u.push(ch)
        }
        ch = path[p++]
        break

      case 'dot':
        if (ch === '/') {
          state = 'slash'
          u.pop()
        } else if (ch === '.') {
          state = 'dot_dot'
          u.push(ch)
        } else if (ch === '%') {
          quotedState = state
          state = 'quoted'
        } else if (ch === '#') {
          u.pop()
          return { ok: true, uri: u.join('') }
        } else {
          state = 'usual'
          u.push(ch)
        }
        ch = path[p++]
        break

      case 'dot_dot':
        if (ch === '/' || ch === '#') {
          if (!up()) return bad('above_root')
          if (ch === '#') return { ok: true, uri: u.join('') }
          state = 'slash'
        } else if (ch === '%') {
          quotedState = state
          state = 'quoted'
        } else {
          state = 'usual'
          u.push(ch)
        }
        ch = path[p++]
        break

      case 'quoted': {
        const d = hex(ch)
        if (d < 0) return bad('bad_escape')
        decoded = d
        state = 'quoted_second'
        ch = path[p++]
        break
      }

      case 'quoted_second': {
        const d = hex(ch)
        if (d < 0) return bad('bad_escape')
        const c = String.fromCharCode(decoded * 16 + d)
        if (c === '\0') return bad('nul')
        if (c === '%' || c === '#' || c === '?') {
          // Kept as a plain character, never decoded again or read as a fragment or query.
          state = 'usual'
          u.push(c)
          ch = path[p++]
        } else {
          // Read again as if it had been sent plain: a decoded / or . takes part in merging and dot segments.
          state = quotedState
          ch = c
        }
        break
      }
    }
  }

  if (state === 'quoted' || state === 'quoted_second') return bad('bad_escape')
  if (state === 'dot') u.pop()
  else if (state === 'dot_dot' && !up()) return bad('above_root')
  return { ok: true, uri: u.join('') }
}
