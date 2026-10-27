import type { SecretGuardVault } from '../types'
import { PLACEHOLDER } from './detect'

// A Bash command gets each value as `$(cat '<file>')`, never as text: the
// value then stays out of the command line `ps` and /proc/<pid>/cmdline show.
// The read is quoted for where the placeholder stands, so the value is one
// word whatever it holds.

type Quote = 'plain' | 'single' | 'double'

// A heredoc body and ANSI-C quoting (`$'…'`) follow rules this scanner does
// not track; such a command takes the values as text, as before.
const HEREDOC = /<<-?\s*['"]?[A-Za-z_]/
const ANSI_C = /\$'/

const read = (path: string, quote: Quote) =>
  quote === 'double' ? `$(cat '${path}')` : quote === 'single' ? `'"$(cat '${path}')"'` : `"$(cat '${path}')"`

export type Injection = {
  command: string
  /** Placeholder id to the value its file holds. */
  files: Record<string, string>
  missing: string[]
}

/** Rewrites `command` to read each value from `<dir>/<id>`; undefined when the command is one this cannot quote. */
export function inject(command: string, vault: SecretGuardVault, dir: string): Injection | undefined {
  const bare = command.replace(PLACEHOLDER, '')
  if (HEREDOC.test(bare) || ANSI_C.test(bare)) return undefined
  const files: Record<string, string> = {}
  const missing: string[] = []
  let out = ''
  let quote: Quote = 'plain'
  let i = 0
  const at = new RegExp(PLACEHOLDER.source, 'y')
  while (i < command.length) {
    at.lastIndex = i
    const m = at.exec(command)
    if (m) {
      const [whole, , id] = m as unknown as [string, string, string]
      const entry = vault[id]
      if (entry) {
        files[id] = entry.value
        out += read(`${dir}/${id}`, quote)
      } else {
        missing.push(whole)
        out += whole
      }
      i += whole.length
      continue
    }
    const c = command[i]!
    if (c === '\\' && quote !== 'single') {
      out += command.slice(i, i + 2)
      i += 2
      continue
    }
    if (c === "'" && quote !== 'double') quote = quote === 'single' ? 'plain' : 'single'
    else if (c === '"' && quote !== 'single') quote = quote === 'double' ? 'plain' : 'double'
    out += c
    i++
  }
  return { command: out, files, missing }
}
