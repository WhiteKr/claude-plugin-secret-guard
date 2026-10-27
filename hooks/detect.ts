import type { SecretGuardVault } from '../types'

// The value is the first of `groups` that matched (the whole match when none
// is given); every pattern carries the `d` flag so its indices are exact.
// `isDummy` turns down a match the pattern alone cannot tell from a non-secret.
type Rule = {
  kind: string
  pattern: RegExp
  groups?: readonly number[]
  isAssignment?: true
  isDummy?: (value: string, m: RegExpMatchArray) => boolean
}

type Span = { start: number; end: number; kind: string; value: string; priority: number }

const KNOWN = -1

const NAME = String.raw`[\w.-]{0,40}(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|client[_-]?secret|auth(?!or)|credential)[\w.-]{0,40}`

const FILE_EXT = String.raw`\.(?:ya?ml|json|toml|env|ini|cfg|conf|properties|xml|html?|md|txt|sh|[cm]?[jt]sx?|py|rb|go|rs|java|kt|php|cs|swift)`

const isUserPassword = (value: string) => {
  try {
    return /^[ -~]+:[ -~]+$/.test(atob(value))
  } catch {
    return false
  }
}

// Ordered by priority: when two spans start at the same place and are as long, the earlier rule names the kind.
const RULES: readonly Rule[] = [
  { kind: 'private-key', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/dg },
  { kind: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}/dg },
  { kind: 'github-token', pattern: /\bgithub_pat_[A-Za-z0-9_]{50,}/dg },
  { kind: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/dg },
  // A real key always has a digit; `sk-learn-pipeline-...` is a name.
  { kind: 'openai-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/dg, isDummy: value => !/\d/.test(value) },
  { kind: 'aws-access-key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/dg },
  { kind: 'slack-token', pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/dg },
  { kind: 'gitlab-token', pattern: /\bglpat-[A-Za-z0-9_-]{20,}/dg },
  { kind: 'google-key', pattern: /\bAIza[0-9A-Za-z_-]{35}/dg },
  { kind: 'stripe-key', pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/dg },
  { kind: 'npm-token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/dg },
  { kind: 'google-client-secret', pattern: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/dg },
  { kind: 'huggingface-token', pattern: /\bhf_[A-Za-z0-9]{30,}\b/dg, isDummy: value => !/\d/.test(value) },
  { kind: 'sendgrid-key', pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/dg },
  { kind: 'digitalocean-token', pattern: /\bdo[opr]_v1_[0-9a-f]{64}\b/dg },
  { kind: 'telegram-token', pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/dg },
  // A webhook URL is its own credential; the host and ids stay readable.
  { kind: 'webhook-token', pattern: /\bhttps:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/([A-Za-z0-9_-]{60,})/dg, groups: [1] },
  { kind: 'webhook-token', pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/([A-Za-z0-9]{20,})/dg, groups: [1] },
  { kind: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/dg },
  { kind: 'bearer-token', pattern: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/dg, groups: [1] },
  // Base64 words follow `Basic` in prose too (`Basic usage`); credentials decode to `user:password`.
  { kind: 'basic-auth', pattern: /\bBasic\s+([A-Za-z0-9+/]{12,}={0,2})(?![\w+/=])/dg, groups: [1], isDummy: value => !isUserPassword(value) },
  // Values are printable ASCII: Read output marks line ends and spaces with
  // glyphs such as U+240A and U+00B7, which must not join the value.
  // A password that repeats the user or the scheme (`postgres:postgres@`,
  // `redis://default:redis@`) is a local default; the user may be empty.
  {
    kind: 'url-password',
    pattern: /\b([a-z][a-z0-9+.-]*):\/\/((?:(?![:/@])[!-~])*):((?:(?![:/@])[!-~])+)(?=@)/dgi,
    groups: [3],
    isDummy: (value, m) => value === m[2] || value.toLowerCase() === m[1]!.toLowerCase(),
  },
  // A quoted value runs to its closing quote; a bare one stops at whitespace, `;` or `,`.
  // Key and value share a line. A key that is a file name (`test_auth.py`)
  // or an ARN segment is none, nor is one followed by `::` (a test id) or
  // `:12:` (a grep hit), where the assignment may come after.
  {
    kind: 'password',
    pattern: new RegExp(
      String.raw`\b(?<!\barn:\S{0,100})(${NAME})(?<!${FILE_EXT})["']?[ \t·→]*(?::=|[:=](?![:=>]|\d+:))[ \t·→]*(?:"((?:(?!["\\])[ -~]){8,})"|'((?:(?!['\\])[ -~]){8,})'|((?:(?![;,"'\`])[!-~]){8,}))`,
      'dgi',
    ),
    groups: [2, 3, 4],
    isAssignment: true,
  },
]

// Hashes and ids, a secret's shape too (`openssl rand -hex 32`, a UUID client
// secret): an assignment's is exempt only where its key says hash or id.
const DIGEST: readonly RegExp[] = [
  /^[0-9a-f]{40}$/i,
  /^[0-9a-f]{64}$/i,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
]
const DIGEST_KEY = /sha|hash|commit|digest|checksum|etag|uuid/i

const EXEMPT: readonly RegExp[] = [
  /^\$/,
  /\{\{.*\}\}/,
  /^(?:process\.env|os\.environ|os\.getenv|import\.meta\.env|ENV\[)/,
  /^(?:changeme|change_me|replace_?me|example|placeholder|dummy|redacted|password|secret|none|null|undefined|true|false)$/i,
  /^your[_-]/i,
  /^<.*>$/,
  /^\*+$/,
  /^(.)\1*$/,
  // A format or template slot the value is filled into later: printf and
  // Python `%` styles, `str.format` and f-string braces. Percent-encoding
  // (`%2F`) is a real password's, so the conversion letter is lowercase.
  /^%(?:\([\w.]+\))?[-+ #0]*\d*(?:\.\d+)?[sdvqr]$/,
  /^\{[\w.!:[\]]*\}$/,
]

// A masked dummy (`sk-xxxxxxxxxxxx`, `ab12......`): the run covers most of the value.
const isMasked = (value: string) => {
  const run = value.match(/([xX*.])\1{5,}/)
  return run !== null && run[0].length * 2 >= value.length
}

// Code on the right of an assignment: a dotted name, a camel or Pascal name, a call.
const CODE_NAME: readonly RegExp[] = [
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/,
  /^_*[a-z]+(?:[A-Z][a-z]*)+$/,
  /^(?:[A-Z][a-z]+){2,}$/,
  /^[A-Za-z_$][\w$.]*\(/,
]

export const PLACEHOLDER = /<<secret:([a-z0-9-]+):([0-9a-f]{12})>>/g

/** A known value shorter than this would shred unrelated text wherever it is looked for. */
export const MIN_KNOWN = 8

export const placeholder = (label: string, id: string) => `<<secret:${label}:${id}>>`

export const IS_PLACEHOLDER = new RegExp(`^${PLACEHOLDER.source}$`)

// A placeholder the model copied a little wrong (an id cut short, one `>`),
// or the notation itself (`<<secret:LABEL:ID>>` in the docs and in the note
// on every redacted row), reads as a `secret: value` assignment and would be
// wrapped again.
const LOOSE_PLACEHOLDER = /<<secret:[A-Za-z0-9-]+:[^\s<>`'"]*>*/g

// A placeholder quoted without its brackets (`url-password:afe8c904c2e6`) names a secret, it holds none.
const LABELS = [...new Set([...RULES.map(rule => rule.kind), 'user'])].join('|')
const BARE_PLACEHOLDER = new RegExp(String.raw`\b(?:secret:)?(?:${LABELS})(?:-b64)?:[0-9a-f]{12}\b`, 'g')

const hex = (bytes: ArrayBuffer | Uint8Array) =>
  Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('')

export const randomSalt = () => hex(crypto.getRandomValues(new Uint8Array(32)))

const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))

const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length)
  out.set(a)
  out.set(b, a.length)
  return out
}

// HMAC-SHA256 (RFC 2104) by hand: the hooks environment's crypto.subtle has digest alone.
export async function idFor(salt: string, value: string): Promise<string> {
  const encode = new TextEncoder()
  let key = encode.encode(salt)
  if (key.length > 64) key = await sha256(key)
  const block = new Uint8Array(64)
  block.set(key)
  const inner = await sha256(concat(block.map(b => b ^ 0x36), encode.encode(value)))
  return hex(await sha256(concat(block.map(b => b ^ 0x5c), inner))).slice(0, 12)
}

const base64Of = new Map<string, string>()
const base64 = (value: string) => {
  let b64 = base64Of.get(value)
  if (b64 === undefined) {
    b64 = btoa(Array.from(new TextEncoder().encode(value), b => String.fromCharCode(b)).join('')).replace(/=+$/, '')
    base64Of.set(value, b64)
  }
  return b64
}

// Keys that point at a secret rather than hold one (`secretName`, `private_key_path`, `token_endpoint`).
const KEY_REFERENCE = /(?:name|ref|path|file|url|uri|endpoint|header|id)$/i

// URLs and filesystem paths.
const LOCATION = /^(?:[a-z][a-z0-9+.-]*:\/\/|[~.]?\/)/i

// Code in a bare value: a type (`string):`, `string[]`, `Record<string`), an
// index or call, a negation. Such a password would need quoting in a shell.
const BARE_CODE = /[()[\]{}<>]|^!/

// Words in quotes: a label or a prompt (`'Publish token'`, `'npm password: '`).
const PHRASE = /^[A-Za-z]+(?: [A-Za-z]+)+:? ?$/

const isExempt = (value: string, rule: Rule, m: RegExpMatchArray, isQuoted: boolean) => {
  if (EXEMPT.some(re => re.test(value)) || isMasked(value) || rule.isDummy?.(value, m)) return true
  if (!rule.isAssignment) return DIGEST.some(re => re.test(value))
  const key = m[1] ?? ''
  if (DIGEST.some(re => re.test(value))) return DIGEST_KEY.test(key)
  if (KEY_REFERENCE.test(key) || LOCATION.test(value)) return true
  const hasDigit = /\d/.test(value)
  // A leading capital is a word's (`Required`), not a mixed-case secret's.
  const isMixed = /[a-z]/.test(value) && /[A-Z]/.test(value.slice(1))
  if (!hasDigit && !isMixed && !/[^\w.-]/.test(value)) return true
  // Counts, timestamps and dates (`input_tokens: 123456789`, `secret_version: 2024-10-22`).
  if (!/[A-Za-z]/.test(value)) return true
  if (!isQuoted) return BARE_CODE.test(value) || CODE_NAME.some(re => re.test(value))
  return !hasDigit && (PHRASE.test(value) || CODE_NAME.some(re => re.test(value)))
}

const isWordChar = (c: string | undefined) => c !== undefined && /\w/.test(c)

// A known value glued to more word characters (`postgres` in `postgresql`,
// `Pa55word1` in `Pa55word123`) is part of another word. One that reads as a
// word (`helpdesk`, no digit and one case) joined by `.` or `-` is part of a
// host or a name (`helpdesk.zio.run`, `zio-helpdesk-api`); a token never is.
const isGlued = (text: string, start: number, end: number) => {
  const value = text.slice(start, end)
  const isWord = !/\d/.test(value) && !(/[a-z]/.test(value) && /[A-Z]/.test(value.slice(1)))
  const joins = (edge: number, near: number, far: number) =>
    isWordChar(text[edge]) &&
    (isWordChar(text[near]) || (isWord && /[.-]/.test(text[near] ?? '') && isWordChar(text[far])))
  return joins(start, start - 1, start - 2) || joins(end - 1, end, end + 1)
}

function knownSpans(text: string, vault: SecretGuardVault): Span[] {
  const spans: Span[] = []
  for (const { label, value } of Object.values(vault)) {
    if (value.length < MIN_KNOWN) continue
    const forms: [string, string][] = [[value, label]]
    if (!label.endsWith('-b64')) forms.push([base64(value), `${label}-b64`])
    for (const [form, kind] of forms) {
      for (let at = text.indexOf(form); at !== -1; at = text.indexOf(form, at + form.length)) {
        if (isGlued(text, at, at + form.length)) continue
        spans.push({ start: at, end: at + form.length, kind, value: form, priority: KNOWN })
      }
    }
  }
  return spans
}

function ruleSpans(text: string): Span[] {
  const spans: Span[] = []
  RULES.forEach((rule, priority) => {
    for (const m of text.matchAll(rule.pattern)) {
      const group = (rule.groups ?? [0]).find(g => m[g] !== undefined)
      const at = group === undefined ? undefined : m.indices?.[group]
      if (group === undefined || at === undefined) continue
      const [start, end] = at
      const value = text.slice(start, end)
      // The bare-value alternative is the assignment rule's last group.
      const isQuoted = rule.isAssignment === true && group !== rule.groups?.at(-1)
      if (isExempt(value, rule, m, isQuoted)) continue
      spans.push({ start, end, kind: rule.kind, value, priority })
    }
  })
  return spans
}

const overlaps = (a: { start: number; end: number }, b: { start: number; end: number }) =>
  a.start < b.end && b.start < a.end

/**
 * Replaces every secret in `text` with its placeholder: values the vault holds
 * (and their base64), then whatever the rules find. Returns the new entries.
 */
export async function scrub(
  text: string,
  vault: SecretGuardVault,
  idOf: (value: string) => Promise<string>,
): Promise<{ text: string; added: SecretGuardVault }> {
  // A value a rule finds in one spot (a URL's password) can sit elsewhere in
  // the same text in a shape no rule matches; scrub again with it known.
  const added: SecretGuardVault = {}
  for (let current = text; ; ) {
    const r = await scrubOnce(current, { ...vault, ...added }, idOf)
    Object.assign(added, r.added)
    if (r.text === current) return { text: current, added }
    current = r.text
  }
}

async function scrubOnce(
  text: string,
  vault: SecretGuardVault,
  idOf: (value: string) => Promise<string>,
): Promise<{ text: string; added: SecretGuardVault }> {
  const added: SecretGuardVault = {}
  const held = Array.from([...text.matchAll(LOOSE_PLACEHOLDER), ...text.matchAll(BARE_PLACEHOLDER)], m => ({
    start: m.index ?? 0,
    end: (m.index ?? 0) + m[0].length,
  }))
  const candidates = [...knownSpans(text, vault), ...ruleSpans(text)]
    .filter(span => !held.some(h => overlaps(h, span)))
    .sort((a, b) => a.start - b.start || b.end - a.end || a.priority - b.priority)

  const chosen: Span[] = []
  for (const span of candidates) {
    const last = chosen[chosen.length - 1]
    if (!last || span.start >= last.end) chosen.push(span)
  }
  if (chosen.length === 0) return { text, added }

  let out = ''
  let cursor = 0
  for (const span of chosen) {
    const id = await idOf(span.value)
    const entry = vault[id] ?? added[id] ?? { label: span.kind, value: span.value }
    if (!vault[id]) added[id] = entry
    out += text.slice(cursor, span.start) + placeholder(entry.label, id)
    cursor = span.end
  }
  return { text: out + text.slice(cursor), added }
}

/**
 * Puts each placeholder's value back; ids the vault lacks are returned as
 * `missing` with the text left as it was.
 */
export function substitute(text: string, vault: SecretGuardVault): { text: string; missing: string[] } {
  const missing: string[] = []
  const out = text.replace(PLACEHOLDER, (whole, _label: string, id: string) => {
    const entry = vault[id]
    if (entry) return entry.value
    missing.push(whole)
    return whole
  })
  return { text: out, missing }
}
