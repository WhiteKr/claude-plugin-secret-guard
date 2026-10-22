export type SecretGuardEntry = { label: string; value: string }

/** Placeholder id (12 hex of HMAC-SHA256) to the real value; session memory only, never `$.store`. */
export type SecretGuardVault = Record<string, SecretGuardEntry>

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { vault: SecretGuardVault }
  }
}
