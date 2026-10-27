import type { EngineInterface } from 'claude-code'

import type { SecretGuardEntry } from '../types'

// The OS keychain keeps each value under its placeholder id, so a resumed or
// later session can resolve a placeholder its own memory never held.
// Linux goes through libsecret's `secret-tool`, macOS through `security`;
// anywhere else, or when the tool fails, the keychain is simply absent.
type Keyring = {
  save: (id: string, entry: SecretGuardEntry) => Promise<void>
  load: (id: string) => Promise<string | undefined>
}

const SERVICE = 'secret-guard'

function secretTool($: EngineInterface): Keyring {
  return {
    save: async (id, { label, value }) => {
      await $.process.run(['secret-tool', 'store', `--label=${SERVICE} ${label}`, 'app', SERVICE, 'id', id, 'label', label], {
        stdin: value,
      })
    },
    load: async id => {
      const r = await $.process.run(['secret-tool', 'lookup', 'app', SERVICE, 'id', id])
      return r.exitCode === 0 && r.stdout !== '' ? r.stdout : undefined
    },
  }
}

// `security` takes the password only as an argument, so on macOS the value
// shows in that one short-lived process's argv.
function macKeychain($: EngineInterface): Keyring {
  return {
    save: async (id, { label, value }) => {
      await $.process.run(['security', 'add-generic-password', '-U', '-s', SERVICE, '-a', id, '-l', `${SERVICE} ${label}`, '-w', value])
    },
    load: async id => {
      const r = await $.process.run(['security', 'find-generic-password', '-s', SERVICE, '-a', id, '-w'])
      return r.exitCode === 0 ? r.stdout.replace(/\n$/, '') : undefined
    },
  }
}

const NONE: Keyring = { save: async () => {}, load: async () => undefined }

let keyring: Promise<Keyring> | undefined

export function keyringOf($: EngineInterface): Promise<Keyring> {
  keyring ??= (async () => {
    try {
      const os = (await $.process.run(['uname', '-s'])).stdout.trim()
      if (os === 'Darwin') return macKeychain($)
      if (os === 'Linux' && (await $.process.run(['sh', '-c', 'command -v secret-tool'])).exitCode === 0) return secretTool($)
    } catch {}
    return NONE
  })()
  return keyring
}

// Ids already looked up and not found, so a drawing that runs on every frame
// does not start a process for each.
const absent = new Set<string>()

/** Looks up ids the vault lacks; answers only the ones the keychain held. */
export async function recall(
  $: EngineInterface,
  wanted: readonly { id: string; label: string }[],
): Promise<Record<string, SecretGuardEntry>> {
  const found: Record<string, SecretGuardEntry> = {}
  const k = await keyringOf($)
  for (const { id, label } of wanted) {
    if (absent.has(id) || found[id]) continue
    const value = await k.load(id).catch(() => undefined)
    if (value === undefined) absent.add(id)
    else found[id] = { label, value }
  }
  return found
}

/** Saves entries the vault just gained; a keychain that fails leaves the session working from memory. */
export async function remember($: EngineInterface, entries: Record<string, SecretGuardEntry>): Promise<void> {
  const k = await keyringOf($)
  for (const [id, entry] of Object.entries(entries)) {
    absent.delete(id)
    await k.save(id, entry).catch(() => {})
  }
}
