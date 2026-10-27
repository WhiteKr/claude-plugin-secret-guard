import type { SecretGuardVault } from '../types'
import { MIN_KNOWN, PLACEHOLDER, placeholder, substitute } from './detect'

// What the person sees where the model sees a placeholder. Drawing only: the
// stored rows the model reads keep the placeholder.
export const ICON = '🙈'
export const ICON_SHOWN = '🐵'

const FENCE = /^\s*(?:```|~~~)/

// A placeholder the model already wrapped in inline code takes both its backticks with it.
const SHOWN = new RegExp(`\`${PLACEHOLDER.source}\`|${PLACEHOLDER.source}`, 'g')

const HAS_PLACEHOLDER = new RegExp(PLACEHOLDER.source)

const labelId = (m: RegExpMatchArray) => ({ label: m[1] ?? m[3] ?? '', id: m[2] ?? m[4] ?? '' })

// The vault sorted longest value first, kept while the vault object is the same.
let sortedFor: SecretGuardVault | undefined
let sorted: [string, { label: string; value: string }][] = []

/**
 * Values the screen shows raw (a tool's own record, a prompt as typed) become
 * placeholders again, longest first so one value inside another stays whole.
 */
export function markKnown(text: string, vault: SecretGuardVault): string {
  if (sortedFor !== vault) {
    sortedFor = vault
    sorted = Object.entries(vault)
      .filter(([, entry]) => entry.value.length >= MIN_KNOWN)
      .sort(([, a], [, b]) => b.value.length - a.value.length)
  }
  let out = text
  for (const [id, { label, value }] of sorted) {
    if (out.includes(value)) out = out.split(value).join(placeholder(label, id))
  }
  return out
}

/**
 * For text drawn as is (a prompt, a tool row's input or output): the icon
 * before the value. A placeholder the vault lacks stays as written.
 */
export function showPlain(text: string, vault: SecretGuardVault): string {
  return markKnown(text, vault).replace(SHOWN, (...m) => {
    const value = vault[labelId(m as unknown as RegExpMatchArray).id]?.value
    return value === undefined ? m[0] : ICON + value
  })
}

export type Piece = { text: string } | { secret: { label: string; value?: string } }

/** A reply as drawn: markdown the surface draws, or lines holding a secret this mod draws itself. */
export type Part = { kind: 'markdown'; text: string } | { kind: 'lines'; isCode: boolean; lines: Piece[][] }

const LIST_ITEM = /^(\s*)[-*+]\s+/

function pieces(line: string, vault: SecretGuardVault): Piece[] {
  const out: Piece[] = []
  let cursor = 0
  for (const m of line.matchAll(SHOWN)) {
    const at = m.index ?? 0
    if (at > cursor) out.push({ text: line.slice(cursor, at) })
    const { label, id } = labelId(m)
    out.push({ secret: { label, value: vault[id]?.value } })
    cursor = at + m[0].length
  }
  if (cursor < line.length) out.push({ text: line.slice(cursor) })
  return out
}

/**
 * Splits a reply into blocks (blank-line paragraphs, whole fences); the blocks
 * that hold a placeholder become lines of pieces, the rest stay markdown.
 * Undefined when the reply holds none.
 */
export function layout(text: string, vault: SecretGuardVault): Part[] | undefined {
  if (!HAS_PLACEHOLDER.test(text)) return undefined
  const blocks: { lines: string[]; isCode: boolean }[] = []
  let current: { lines: string[]; isCode: boolean } | undefined
  for (const line of text.split('\n')) {
    if (current?.isCode) {
      current.lines.push(line)
      if (FENCE.test(line)) current = undefined
    } else if (FENCE.test(line)) {
      current = { lines: [line], isCode: true }
      blocks.push(current)
    } else if (line.trim() === '') {
      current = undefined
      blocks.push({ lines: [line], isCode: false })
    } else {
      if (!current) blocks.push((current = { lines: [], isCode: false }))
      current.lines.push(line)
    }
  }
  const parts: Part[] = []
  for (const block of blocks) {
    const joined = block.lines.join('\n')
    const last = parts[parts.length - 1]
    if (!HAS_PLACEHOLDER.test(joined)) {
      if (last?.kind === 'markdown') last.text += '\n' + joined
      else parts.push({ kind: 'markdown', text: joined })
      continue
    }
    const lines = block.isCode ? block.lines.filter(l => !FENCE.test(l)) : block.lines
    parts.push({
      kind: 'lines',
      isCode: block.isCode,
      lines: lines.map(l => pieces(block.isCode ? l : l.replace(LIST_ITEM, '$1• '), vault)),
    })
  }
  return parts
}

// A link's target only names the id; `.invalid` never resolves, so a surface
// that opens the link instead of reporting the press goes nowhere.
export const LINK_BASE = 'https://secret.invalid/'

const BLOCK_LABEL = '코드 블록 전체'

/** A reply as markdown the surface draws whole, each secret a link whose press copies it. */
export type Linked = { text: string; links: Record<string, { label: string; value: string }> }

/**
 * Turns each placeholder into a link the surface draws in place, so the
 * reply keeps its own headings, tables and code. Code draws no links: a
 * placeholder there shows its name, and a line after the code block or the
 * paragraph holds the links for those. A code block whose secrets are all
 * known also gets a link that copies the whole block with the real values.
 * Undefined when the reply holds none.
 */
export function linked(text: string, vault: SecretGuardVault): Linked | undefined {
  if (!HAS_PLACEHOLDER.test(text)) return undefined
  const links: Linked['links'] = {}
  const out: string[] = []
  let pending = new Map<string, string>()
  let isFence = false
  let block: string[] = []
  const link = (label: string, id: string) => {
    const value = vault[id]?.value
    if (value === undefined) return `${ICON} ${label}`
    links[LINK_BASE + id] = { label, value }
    return `[${ICON} ${label}](${LINK_BASE}${id})`
  }
  const flush = (whole?: string) => {
    if (pending.size === 0) return
    const each = [...pending].map(([id, label]) => link(label, id))
    out.push('', [...(whole ? [whole] : []), ...each].join(' · '))
    pending = new Map()
  }
  // The block's link is keyed by its order, so its target never holds the block's text.
  const blockLink = () => {
    const raw = block.join('\n')
    if (!HAS_PLACEHOLDER.test(raw)) return undefined
    const r = substitute(raw, vault)
    if (r.missing.length > 0) return undefined
    const href = `${LINK_BASE}block-${Object.keys(links).filter(k => k.includes('/block-')).length + 1}`
    links[href] = { label: BLOCK_LABEL, value: r.text }
    return `[${ICON} ${BLOCK_LABEL}](${href})`
  }
  for (const line of text.split('\n')) {
    if (FENCE.test(line)) {
      out.push(line)
      if (isFence) flush(blockLink())
      isFence = !isFence
      block = []
      continue
    }
    if (isFence) block.push(line)
    if (!isFence && line.trim() === '') flush()
    out.push(
      line.replace(SHOWN, (whole, ...m) => {
        const at = m[m.length - 2] as number
        const { label, id } = labelId([whole, ...m] as unknown as RegExpMatchArray)
        const inCode = isFence || (line.slice(0, at).split('`').length - 1) % 2 === 1
        if (!inCode) return link(label, id)
        if (vault[id]) pending.set(id, label)
        return `${ICON}${label}`
      }),
    )
  }
  flush()
  return { text: out.join('\n'), links }
}

/** Applies `f` to every string in a JSON-shaped value; unchanged parts keep their identity. */
export function mapStrings(value: unknown, f: (text: string) => string): unknown {
  if (typeof value === 'string') return f(value)
  if (Array.isArray(value)) {
    const items = value.map(v => mapStrings(v, f))
    return items.some((v, i) => v !== value[i]) ? items : value
  }
  if (value !== null && typeof value === 'object') {
    let isChanged = false
    const entries = Object.entries(value).map(([k, v]) => {
      const next = mapStrings(v, f)
      if (next !== v) isChanged = true
      return [k, next] as const
    })
    return isChanged ? Object.fromEntries(entries) : value
  }
  return value
}
