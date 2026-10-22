import { Check, Copy, Download } from 'lucide-react'
import { useState } from 'react'
import { CodeLines } from './CodeLines'

export function CopyButton({ text, label = 'Copy', compact = false }: { text: string; label?: string; compact?: boolean }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      setState('failed')
    }
    window.setTimeout(() => setState('idle'), 2000)
  }

  const words = state === 'copied' ? 'Copied' : state === 'failed' ? 'Select and copy it instead' : label
  return (
    <button
      type="button"
      className={`button button--secondary${compact ? ' button--compact' : ''}`}
      onClick={copy}
      aria-label={compact && state === 'idle' ? label : undefined}
    >
      {state === 'copied' ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      <span className={compact && state === 'idle' ? 'sr-only' : undefined} aria-live="polite">
        {words}
      </span>
    </button>
  )
}

export function DownloadButton({ text, fileName }: { text: string; fileName: string }) {
  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = fileName
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <button type="button" className="button button--secondary" onClick={download}>
      <Download aria-hidden="true" />
      <span>Download</span>
    </button>
  )
}

/** A shell command in a terminal strip, with its own copy button. */
export function CommandBlock({ code, label }: { code: string; label: string }) {
  return (
    <div className="command">
      <span className="command__prompt mono" aria-hidden="true">
        $
      </span>
      <CodeLines code={code} language="shell" wrap label={label} />
      <CopyButton text={code} label={`Copy: ${label}`} compact />
    </div>
  )
}
