// A small tokenizer for the two languages the page shows: the nginx exception file and one-line shell commands.

export type TokenKind = 'comment' | 'keyword' | 'variable' | 'string' | 'number' | 'operator' | 'flag' | 'command' | 'text'
export interface Token {
  kind: TokenKind
  text: string
}

const NGINX = /(#.*$)|("(?:[^"\\]|\\.)*")|(\$[A-Za-z0-9_]+)|\b(set|if|return|include)\b|(~\*|~|!=|=)|\b(\d+)\b|([{}();])/g
const SHELL = /('(?:[^']|'\\'')*')|(\s-{1,2}[A-Za-z][\w-]*)|(&&|\|\|?)|((?:^|(?<=&&\s))[a-z][\w.-]*)/g

function tokenize(line: string, re: RegExp, kinds: (TokenKind | undefined)[]): Token[] {
  const out: Token[] = []
  let last = 0
  for (const m of line.matchAll(re)) {
    const i = m.index
    if (i > last) out.push({ kind: 'text', text: line.slice(last, i) })
    const group = m.slice(1).findIndex((g) => g !== undefined)
    out.push({ kind: kinds[group] ?? 'text', text: m[0] })
    last = i + m[0].length
  }
  if (last < line.length) out.push({ kind: 'text', text: line.slice(last) })
  return out
}

export function highlightNginx(source: string): Token[][] {
  return source
    .replace(/\n$/, '')
    .split('\n')
    .map((l) => tokenize(l, NGINX, ['comment', 'string', 'variable', 'keyword', 'operator', 'number', 'text']))
}

export function highlightShell(source: string): Token[][] {
  return source.split('\n').map((l) => tokenize(l, SHELL, ['string', 'flag', 'operator', 'command']))
}
