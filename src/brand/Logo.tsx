import { LOGO } from './logoPaths'

/** The [7G] Helper lockup: brackets in the accent, letters in the text color. Outlined, so no font is needed. */
export function Logo({ height = 30, title = '7G Helper' }: { height?: number; title?: string }) {
  return (
    <svg
      className="logo"
      viewBox={`0 0 ${LOGO.width} ${LOGO.height}`}
      height={height}
      width={(height * LOGO.width) / LOGO.height}
      role="img"
      aria-label={title}
    >
      <path d={LOGO.brackets} fill="none" stroke="var(--color-accent)" strokeWidth={LOGO.bracketStroke} strokeLinecap="square" />
      <path d={LOGO.sevenG} fill="currentColor" />
      <path d={LOGO.helper} fill="currentColor" />
    </svg>
  )
}
