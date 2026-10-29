import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallInput } from 'claude-code'

import type { SecretGuardVault } from '../types'
import { IS_PLACEHOLDER, MIN_KNOWN, PLACEHOLDER, idFor, placeholder, randomSalt, scrub, substitute } from './detect'
import { layout, linked, mapStrings, showPlain } from './display'
import { inject } from './inject'
import { recall, remember } from './keyring'
import { drawLinked, drawMessage } from './reveal'

type Block = { type: string; [field: string]: unknown }

const vault = atom({ plugin: 'secret-guard', key: 'vault' } as const, {})

const HIDDEN = '[secret-guard: 내용을 검사하지 못해 숨김]'

// What a tool does with a placeholder in its input. Tools that read or write a
// local file or run a local process get the real value; their output is
// scrubbed again. Tools that reach the network get nothing: they would act on
// the placeholder text itself (an MCP call could store it as a CI secret), and
// text injected into the conversation cannot have a secret sent out. The
// desktop app's own MCP tools (`mcp__ccd_*`, its plan and session cards) stay
// local. Every other tool keeps the placeholder: a handoff to a subagent
// resolves it from the same session vault, and a plan or task list only shows it.
const SUBSTITUTES = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'Bash', 'Read', 'Grep', 'Glob'])
const isNetwork = (tool: string) =>
  tool === 'WebFetch' || tool === 'WebSearch' || (tool.startsWith('mcp__') && !tool.startsWith('mcp__ccd_'))

const HAS_PLACEHOLDER = new RegExp(PLACEHOLDER.source)

const RESERVED = new Set(['tool', 'tool_use_id', 'agentId', 'requestMeta', 'consent'])

const POLICY = {
  id: 'secret-guard:policy',
  scope: 'session',
  text: [
    '# Redacted secrets',
    'secret-guard is active in this session. Strings shaped `<<secret:LABEL:ID>>` stand for credentials it holds for the user; the real values never enter this conversation.',
    'The user installed secret-guard so you can do credential work for them: move a token into `.env`, put a password in a config file, pass a key to a local command or test. Do that work as you would with any other string.',
    '- Edit, Write, MultiEdit, NotebookEdit, Bash, Read, Grep and Glob get the real value in place of the placeholder when the tool runs, and their output comes back redacted.',
    '- WebFetch, WebSearch and MCP tools refuse placeholders. For remote work such as a CI secret, run the CLI in Bash (`gh secret set NAME --body \"<<secret:LABEL:ID>>\"`).',
    '- Do not ask the user to paste a value you already hold as a placeholder, and do not print, encode or slice a value in Bash: a transformed value is not redacted.',
    '- If the user wants a value handled that was not redacted automatically, they can run `/secret <value>` to register it.',
  ].join('\n'),
} as const

const NOTE =
  '[secret-guard] Each <<secret:LABEL:ID>> above stands for a credential secret-guard holds for the user. Use it as-is in Edit, Write or Bash input to work with the real value; it is filled in when the tool runs.'

// One pending read shared by every caller, so two first rows cannot each mint a salt.
let salt: Promise<string> | undefined

function saltOf($: EngineInterface): Promise<string> {
  salt ??= (async () => {
    const stored = await $.store.get('salt')
    if (typeof stored === 'string' && /^[0-9a-f]{64}$/.test(stored)) return stored
    const fresh = randomSalt()
    await $.store.set('salt', fresh)
    return fresh
  })()
  return salt
}

async function scrubber($: EngineInterface) {
  const known: SecretGuardVault = await read($, vault)
  const salt = await saltOf($)
  const added: SecretGuardVault = {}
  return {
    text: async (text: string) => {
      const r = await scrub(text, { ...known, ...added }, value => idFor(salt, value))
      Object.assign(added, r.added)
      return r.text
    },
    commit: async () => {
      if (Object.keys(added).length === 0) return
      await update($, vault, v => ({ ...v, ...added }))
      await remember($, added)
    },
  }
}

/** The vault with any placeholder in `text` it lacks filled from the keychain. */
async function withRecalled($: EngineInterface, text: string): Promise<SecretGuardVault> {
  const known: SecretGuardVault = await read($, vault)
  const wanted = [...text.matchAll(PLACEHOLDER)]
    .map(([, label, id]) => ({ label: label!, id: id! }))
    .filter(({ id }) => !known[id])
  if (wanted.length === 0) return known
  const found = await recall($, wanted)
  if (Object.keys(found).length === 0) return known
  await update($, vault, v => ({ ...found, ...v }))
  return { ...found, ...known }
}

// Bash reads each value from a file in a directory of its own (0700, files
// 0600), made for one call and removed when it returns.
async function injectDir($: EngineInterface): Promise<string> {
  const root = ((await $.env.get('TMPDIR').catch(() => undefined)) ?? '/tmp').replace(/\/+$/, '')
  return `${root}/secret-guard-${randomSalt().slice(0, 16)}`
}

const lingering = new Set<string>()

async function mapTexts(content: readonly Block[], f: (text: string) => Promise<string> | string): Promise<Block[]> {
  const out: Block[] = []
  for (const block of content) {
    if (block.type === 'text' && typeof block.text === 'string') {
      out.push({ ...block, text: await f(block.text) })
    } else if (block.type === 'tool_result' && typeof block.content === 'string') {
      out.push({ ...block, content: await f(block.content) })
    } else if (block.type === 'tool_result' && Array.isArray(block.content)) {
      out.push({ ...block, content: await mapTexts(block.content as Block[], f) })
    } else {
      out.push(block)
    }
  }
  return out
}

// The note rides inside the row's own text (the tool result, or the last text
// block), never as a block of its own, which a surface draws as a message the
// person seemingly sent.
function withNote(content: Block[]): Block[] {
  const result = content.findLastIndex(b => b.type === 'tool_result')
  if (result !== -1) {
    const block = content[result]!
    const inner = block.content
    const noted =
      typeof inner === 'string'
        ? `${inner}\n\n${NOTE}`
        : [...(Array.isArray(inner) ? (inner as Block[]) : []), { type: 'text', text: NOTE }]
    return content.with(result, { ...block, content: noted })
  }
  const last = content.findLastIndex(b => b.type === 'text')
  if (last === -1) return content
  const block = content[last]!
  return content.with(last, { ...block, text: `${String(block.text)}\n\n${NOTE}` })
}

const withoutNote = (text: string) => text.split(`\n\n${NOTE}`).join('').split(NOTE).join('')

const unknownPlaceholder = (whole: string) =>
  `secret-guard: ${whole} 의 값을 이 세션에서 알 수 없습니다. 원본 파일을 다시 Read 하거나 사용자에게 /secret 으로 등록을 요청하세요.`

const refusedTool = (tool: string) =>
  `secret-guard: ${tool} 에는 비밀 값을 넘기지 않습니다. 로컬 파일을 다루거나 명령을 실행하는 도구(${[...SUBSTITUTES].join(', ')})에만 자리표시자를 쓸 수 있습니다.`

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'secret',
      description: '값을 비밀로 등록하고 그 자리표시자를 입력창에 넣는다',
      argumentHint: '<value>',
    })
    return next(e)
  })

  // The policy also rides on every row that had something redacted (a
  // prompt's beside it, at prompt.submit): a
  // higher-tier plugin can pass prompt.compose on past this mod, and the
  // model needs the rule exactly where it first meets a placeholder.
  on('session.append', async ($, e, next) => {
    const s = await scrubber($)
    let isRedacted = false
    const content = await mapTexts(e.message.content, async text => {
      const out = await s.text(text)
      if (out !== text) isRedacted = true
      return out
    })
    const noted = isRedacted && e.message.role === 'user' && e.door !== 'prompt' ? withNote(content) : content
    // The row is checked whole before it is stored: a value a later block
    // revealed may sit raw in an earlier one.
    let checked = noted
    for (let isClean = false; !isClean; ) {
      isClean = true
      checked = await mapTexts(checked, async text => {
        const out = await s.text(text)
        if (out !== text) isClean = false
        return out
      })
    }
    await s.commit()
    return next({ ...e, message: { ...e.message, content: checked } })
  }).catch(async ($, e, next) =>
    next.called
      ? next(e)
      : next({ ...e, message: { ...e.message, content: await mapTexts(e.message.content, () => HIDDEN) } }),
  )

  // A prompt's note rides beside it as context the person never sees: a note
  // in the typed text comes back into the box when the turn is rewound.
  on('prompt.submit', async ($, e, next) => {
    if (e.command) return next(e)
    const s = await scrubber($)
    if ((await s.text(e.text)) === e.text) return next(e)
    return next({ ...e, context: [...(e.context ?? []), NOTE] })
  })

  on('prompt.attachment', async ($, e, next) => {
    const r = await next(e)
    if (r.text === null) return r
    const s = await scrubber($)
    const text = await s.text(r.text)
    await s.commit()
    return { text }
  }).catch(() => ({ text: HIDDEN }))

  on('prompt.context', async ($, e, next) => {
    const r = await next(e)
    const s = await scrubber($)
    const blocks = []
    for (const block of r.blocks) blocks.push({ ...block, text: await s.text(block.text) })
    await s.commit()
    return { ...r, blocks }
  }).catch(($, e) => ({ blocks: e.blocks.map(block => ({ ...block, text: HIDDEN })) }))

  on('tool.call', async ($, e, next) => {
    const tool = String(e.tool)
    if (!SUBSTITUTES.has(tool)) {
      if (!isNetwork(tool)) return next(e)
      const input = Object.fromEntries(Object.entries(e).filter(([key]) => !RESERVED.has(key)))
      return HAS_PLACEHOLDER.test(JSON.stringify(input)) ? { deny: refusedTool(tool) } : next(e)
    }
    const input = Object.fromEntries(Object.entries(e).filter(([key]) => !RESERVED.has(key)))
    const known = await withRecalled($, JSON.stringify(input))
    const missing: string[] = []
    const fields: Record<string, unknown> = {}
    const put = (text: string) => {
      const r = substitute(text, known)
      missing.push(...r.missing)
      return r.text
    }
    const dir = tool === 'Bash' && typeof input.command === 'string' ? await injectDir($) : undefined
    const injection = dir === undefined ? undefined : inject(input.command as string, known, dir)
    for (const [key, value] of Object.entries(input)) {
      if (injection && key === 'command') {
        missing.push(...injection.missing)
        if (injection.command !== value) fields[key] = injection.command
        continue
      }
      const substituted = mapStrings(value, put)
      if (substituted !== value) fields[key] = substituted
    }
    const [first] = missing
    if (first !== undefined) return { deny: unknownPlaceholder(first) }
    if (Object.keys(fields).length === 0) return next(e)
    if (!injection || Object.keys(injection.files).length === 0) return next({ ...e, ...fields } as ToolCallInput)
    for (const [id, value] of Object.entries(injection.files)) {
      const r = await $.process.run(['sh', '-c', 'umask 077 && mkdir -p "$1" && cat > "$1/$2"', 'sh', dir!, id], { stdin: value })
      if (r.exitCode !== 0) return { deny: 'secret-guard: 값을 넘길 임시 파일을 만들지 못해 실행을 막았습니다.' }
    }
    // A background command reads its files after this call returns; they go when the session ends.
    if (input.run_in_background === true) {
      lingering.add(dir!)
      return next({ ...e, ...fields } as ToolCallInput)
    }
    try {
      return await next({ ...e, ...fields } as ToolCallInput)
    } finally {
      await $.process.run(['rm', '-rf', dir!]).catch(() => {})
    }
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: 'secret-guard: 자리표시자를 치환하지 못해 실행을 막았습니다.' },
  )

  // The screen shows the person each real value, marked, where the model has a
  // placeholder; a rewrite here draws the row alone, never what the model reads.
  // A graphical surface draws the reply as its own markdown with each secret a
  // link; the terminal, where a link press may open it instead, keeps the bars.
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    if (!HAS_PLACEHOLDER.test(e.props.text)) return next(e)
    const known = await withRecalled($, e.props.text)
    if (e.surface !== 'terminal') {
      const reply = linked(e.props.text, known)
      return reply ? drawLinked($, e, reply) : next(e)
    }
    const parts = layout(e.props.text, known)
    return parts ? drawMessage($, e, parts) : next(e)
  })

  on('session.end', async ($, e, next) => {
    for (const dir of lingering) await $.process.run(['rm', '-rf', dir]).catch(() => {})
    lingering.clear()
    return next(e)
  })

  // A prompt keeps the surface's own drawing, which a tree of this mod's would
  // replace with a reply's; a value pasted raw is found by the vault.
  on('ui.render', { component: 'UserMessage' }, async ($, e, next) => {
    const text = showPlain(withoutNote(e.props.text), await read($, vault))
    return text === e.props.text ? next(e) : next({ ...e, props: { ...e.props, text } })
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const known = await read($, vault)
    const drawn = (text: string) => showPlain(withoutNote(text), known)
    const input = mapStrings(e.props.input, drawn)
    const output = mapStrings(e.props.output, drawn)
    if (input === e.props.input && output === e.props.output) return next(e)
    // `output` is absent while the call runs, and a key left undefined breaks the row.
    const props = output === e.props.output ? { ...e.props, input } : { ...e.props, input, output }
    return next({ ...e, props })
  })

  on('ui.render', { component: 'ToolResult' }, async ($, e, next) => {
    const known = await read($, vault)
    const output = mapStrings(e.props.output, text => showPlain(withoutNote(text), known))
    return output === e.props.output ? next(e) : next({ ...e, props: { ...e.props, output } })
  })

  on('prompt.compose', async ($, e, next) => {
    const r = await next(e)
    return { sections: [...r.sections.filter(s => s.id !== POLICY.id), POLICY] }
  })

  // Registers the value and passes the placeholder on as the args, so the
  // command's rows and its record carry the placeholder, never the value.
  on('command.run', { command: 'secret' }, async ($, e, next) => {
    const value = e.args.trim()
    if (value.length < MIN_KNOWN) return next({ ...e, args: '' })
    const id = await idFor(await saltOf($), value)
    const held = (await read($, vault))[id]
    const label = held?.label ?? 'user'
    if (!held) {
      await update($, vault, v => ({ ...v, [id]: { label, value } }))
      await remember($, { [id]: { label, value } })
    }
    return next({ ...e, args: placeholder(label, id) })
  }).catch(($, e, next) => (next.called ? next(e) : next({ ...e, args: '' })))

  on('command.run', { command: 'secret' }, async ($, e) => {
    if (!IS_PLACEHOLDER.test(e.args)) {
      return { text: `등록하지 않았습니다. 사용법은 /secret <값>이고, 값은 ${MIN_KNOWN}자 이상이어야 합니다.` }
    }
    await $.prompt.fill({ text: e.args + ' ', mode: 'insert' })
    return { text: `\`${e.args}\` 로 등록됨` }
  })
}
