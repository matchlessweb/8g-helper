/**
 * Binds a sentence's last two words with a no-break space, so no line of it ends on one stranded word. Only when the
 * pair is short: a glued pair wider than its column would push the text off the side, which is worse than an orphan.
 */
export function bindLast(text: string, max = 20): string {
  const s = text.trimEnd()
  const i = s.lastIndexOf(' ')
  if (i < 0 || s.length - s.lastIndexOf(' ', i - 1) - 1 > max) return s
  return `${s.slice(0, i)} ${s.slice(i + 1)}`
}
