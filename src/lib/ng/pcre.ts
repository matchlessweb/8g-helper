// 8G's patterns are PCRE, run by nginx. This reads just enough PCRE to run each one in JavaScript with nginx's meaning,
// and to take one name out of an alternation without breaking the pattern. Anything it does not know, it refuses, so a
// new 8G release with a new construct fails loudly instead of matching differently.
//
// Where PCRE (non-UTF, default tables, newline LF, no flags but caseless) and JavaScript (flag i, no u) differ:
// - `.` in PCRE matches a carriage return; in JavaScript it does not. Written here as [^\n].
// - `$` in PCRE also matches before a final newline; in JavaScript only at the very end. Written as (?=\n?(?![\s\S])).
// - `\s` in JavaScript also matches U+00A0 and other Unicode spaces; in PCRE only tab, LF, VT, FF, CR and space.
// Values are byte strings (one character per byte, 0-255), as nginx sees them, so these are the only gaps that reach
// a real request: a decoded %0d or %0a in $uri, or a raw 0xA0 byte.

export type PcreDifference = 'dot' | 'dollar' | 'space'

export interface Alternative {
  /** Where the alternative starts and ends in the pattern (end is exclusive). */
  start: number
  end: number
}

export interface Alternation {
  /** 'top' is the whole pattern; 'group' a ( ) or (?: ); 'lookaround' a (?= (?! (?<= (?<! assertion. */
  kind: 'top' | 'group' | 'lookaround'
  start: number
  end: number
  alternatives: Alternative[]
}

export interface ParsedPattern {
  /** The pattern in JavaScript syntax, with PCRE's meaning kept where the two differ. */
  js: string
  /** Which differences this pattern contains (and the translation covers). */
  differences: PcreDifference[]
  alternations: Alternation[]
}

const SPACE = '\\t\\n\\v\\f\\r '
const DOLLAR = '(?=\\n?(?![\\s\\S]))'

export function parsePcre(pattern: string): ParsedPattern {
  const out: string[] = []
  const differences = new Set<PcreDifference>()
  const alternations: Alternation[] = []
  const stack: { alt: Alternation; from: number }[] = [
    { alt: { kind: 'top', start: 0, end: pattern.length, alternatives: [] }, from: 0 },
  ]
  let inClass = false
  let afterQuantifier = false
  let i = 0
  const fail = (what: string): never => {
    throw new Error(`unsupported PCRE (${what}) at ${i} in ${pattern}`)
  }

  while (i < pattern.length) {
    const c = pattern[i]
    const wasQuantifier: boolean = afterQuantifier
    afterQuantifier = false

    if (c === '\\') {
      const n = pattern[i + 1]
      if (n === undefined) fail('a trailing backslash')
      if (n === 'x') {
        if (!/^[0-9A-Fa-f]{2}$/.test(pattern.slice(i + 2, i + 4))) fail('\\x without two hex digits')
        out.push(pattern.slice(i, i + 4))
        i += 4
        continue
      }
      if (n === 's') {
        differences.add('space')
        out.push(inClass ? SPACE : `[${SPACE}]`)
      } else if (/[wdbWDB]/.test(n)) {
        if (inClass && /[bB]/.test(n)) fail(`\\${n} in a class`)
        out.push(c + n)
      } else if (/[A-Za-z0-9]/.test(n)) {
        fail(`\\${n}`)
      } else {
        out.push(c + n)
      }
      i += 2
      continue
    }

    if (inClass) {
      if (c === '[' && pattern[i + 1] === ':') fail('a POSIX class')
      if (c === ']') inClass = false
      out.push(c)
      i++
      continue
    }

    switch (c) {
      case '[': {
        inClass = true
        const negated = pattern[i + 1] === '^'
        if (pattern[i + (negated ? 2 : 1)] === ']') fail('a ] first in a class')
        out.push(negated ? '[^' : '[')
        i += negated ? 2 : 1
        continue
      }
      case '(': {
        const prefix = pattern.startsWith('(?<=', i) || pattern.startsWith('(?<!', i)
          ? 4
          : pattern.startsWith('(?:', i) || pattern.startsWith('(?=', i) || pattern.startsWith('(?!', i)
            ? 3
            : pattern[i + 1] === '?'
              ? fail('a group type')
              : 1
        const kind = prefix === 1 || pattern[i + 2] === ':' ? 'group' : 'lookaround'
        stack.push({ alt: { kind, start: i + prefix, end: -1, alternatives: [] }, from: i + prefix })
        out.push(pattern.slice(i, i + prefix))
        i += prefix
        continue
      }
      case ')': {
        const top = stack.pop()!
        if (stack.length === 0) fail('an unmatched )')
        top.alt.alternatives.push({ start: top.from, end: i })
        top.alt.end = i
        alternations.push(top.alt)
        out.push(c)
        i++
        continue
      }
      case '|': {
        const top = stack[stack.length - 1]
        top.alt.alternatives.push({ start: top.from, end: i })
        top.from = i + 1
        out.push(c)
        i++
        continue
      }
      case '.':
        differences.add('dot')
        out.push('[^\\n]')
        i++
        continue
      case '$':
        differences.add('dollar')
        out.push(DOLLAR)
        i++
        continue
      case '*':
      case '+':
      case '?':
        if (c === '+' && wasQuantifier) fail('a possessive quantifier')
        out.push(c)
        afterQuantifier = c !== '?' || !wasQuantifier
        i++
        continue
      case '{': {
        const q = pattern.slice(i).match(/^\{\d+(?:,\d*)?\}/)
        if (q) {
          out.push(q[0])
          afterQuantifier = true
          i += q[0].length
          continue
        }
        out.push(c)
        i++
        continue
      }
      default:
        out.push(c)
        i++
    }
  }

  if (inClass) fail('an unclosed class')
  if (stack.length !== 1) fail('an unclosed group')
  const top = stack[0]
  top.alt.alternatives.push({ start: top.from, end: pattern.length })
  alternations.push(top.alt)
  return { js: out.join(''), differences: [...differences], alternations }
}

/** A PCRE pattern as a JavaScript RegExp with nginx's ~* meaning: case-insensitive, PCRE semantics kept. */
export function compilePcre(pattern: string): RegExp {
  return new RegExp(parsePcre(pattern).js, 'i')
}

export interface Removal {
  /** The alternative taken out, as the pattern spells it, e.g. ahrefs. */
  text: string
  /** The alternative itself in the pattern. */
  altStart: number
  altEnd: number
  /** What to delete: the alternative and one | beside it, so no empty alternative or dangling | is left. */
  start: number
  end: number
}

/** Every alternative that can be taken out cleanly: from a top-level or ( ) alternation with two or more, never empty. */
export function removals(pattern: string): Removal[] {
  const out: Removal[] = []
  for (const a of parsePcre(pattern).alternations) {
    if (a.kind === 'lookaround' || a.alternatives.length < 2) continue
    a.alternatives.forEach((alt, k) => {
      if (alt.end === alt.start) return
      const start = k > 0 ? a.alternatives[k - 1].end : alt.start
      const end = k > 0 ? alt.end : a.alternatives[1].start
      out.push({ text: pattern.slice(alt.start, alt.end), altStart: alt.start, altEnd: alt.end, start, end })
    })
  }
  return out
}

/** A removal's text looks like a plain name (letters, digits, - and _, an escaped dot, \b, an optional letter). */
export function isNameLike(text: string): boolean {
  return /^(?:[A-Za-z0-9_-]\??|\\[.b-])+$/.test(text) && (text.match(/[A-Za-z0-9]/g)?.length ?? 0) >= 2
}

/** True when the pattern has an empty alternative, an empty group, or a | at either end of an alternation. */
export function hasEmptyAlternative(pattern: string): boolean {
  return parsePcre(pattern).alternations.some((a) => a.alternatives.some((alt) => alt.end === alt.start))
}
