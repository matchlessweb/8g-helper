import { ArrowUpRight } from 'lucide-react'

/**
 * Every link that leaves the site: a new tab, the up-right arrow, and a note for screen readers.
 * The arrow is glued to the last word so a wrap can never strand it on a line of its own.
 */
export function ExternalLink({ href, children, className }: { href: string; children: string; className?: string }) {
  const cut = children.lastIndexOf(' ')
  const head = cut === -1 ? '' : children.slice(0, cut + 1)
  const tail = cut === -1 ? children : children.slice(cut + 1)
  return (
    <a href={href} className={className ? `extlink ${className}` : 'extlink'} target="_blank" rel="noopener noreferrer">
      {/* One wrapper, so a flex parent cannot split the words into items and drop the space between them. */}
      <span className="extlink__label">
        {head}
        <span className="extlink__tail">
          {tail}
          <ArrowUpRight className="extlink__icon" aria-hidden="true" />
        </span>
        <span className="sr-only"> (opens in a new tab)</span>
      </span>
    </a>
  )
}
