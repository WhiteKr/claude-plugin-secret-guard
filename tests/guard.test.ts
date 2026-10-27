import { expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On, SessionAppendInput, ToolCallInput } from 'claude-code'

import { idFor } from '../hooks/detect'

// Key-shaped values are assembled at run time so no file holds one.
const GH = 'gh' + 'p_' + 'A1b2'.repeat(9)
const PLACEHOLDER = /<<secret:([a-z0-9-]+):([0-9a-f]{12})>>/
const HIDDEN = '[secret-guard: 내용을 검사하지 못해 숨김]'

let rows = 0

const toolResult = (text: string): SessionAppendInput => ({
  message: {
    type: 'user',
    role: 'user',
    content: [{ type: 'tool_result', tool_use_id: `tu${rows}`, content: text }],
  },
  door: 'tool-result',
  origin: { kind: 'tool', tool: 'Read' },
  uuid: `row-${++rows}`,
})

const textOf = (row: SessionAppendInput | undefined) =>
  (row?.message.content ?? [])
    .map(b => (b.type === 'tool_result' ? String(b.content) : b.type === 'text' ? String(b.text) : ''))
    .join('\n')
    .replace(/\n\n\[secret-guard\] .*$/, '')

async function setup($: Engine, on: On) {
  const session = mock.session(on)
  mock.store(on)
  const calls: ToolCallInput[] = []
  on('tool.call', (_, e) => {
    calls.push(e)
    return { result: {} }
  })
  const drawn: Record<string, Record<string, unknown>> = {}
  on('ui.render', (_, e) => {
    drawn[e.component] = e.props as Record<string, unknown>
    return { type: 'engine', ref: 0 } as never
  })
  const store = async (text: string) => {
    await $.session.append(toolResult(text))
    return textOf(session.appended().at(-1))
  }
  const draw = async (component: string, props: Record<string, unknown>) => {
    await $.ui.render({ surface: 'desktop', component, requestId: 'r1', props } as never)
    return drawn[component] ?? {}
  }
  return { store, calls, draw }
}

test('a token in a tool result is stored as a placeholder, never raw', async ($, on) => {
  const { store } = await setup($, on)
  const stored = await store(`GITHUB_TOKEN=${GH}\nOTHER=1`)
  expect(stored).not.toContain(GH)
  expect(stored).toMatch(/^GITHUB_TOKEN=<<secret:github-token:[0-9a-f]{12}>>\nOTHER=1$/)
})

test('a row with a redaction tells the model how to use the placeholder, a clean row does not', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  await $.session.append(toolResult(`GITHUB_TOKEN=${GH}`))
  await $.session.append(toolResult('nothing secret here'))
  const [redacted, clean] = session.appended().slice(-2).map(row => row.message.content)
  expect(redacted).toHaveLength(1)
  expect(String(redacted?.[0]?.type === 'tool_result' && redacted[0].content)).toContain('\n\n[secret-guard] ')
  expect(JSON.stringify(clean)).not.toContain('[secret-guard] ')
})

test('the same value always gets the same placeholder', async ($, on) => {
  const { store } = await setup($, on)
  const first = (await store(`token: ${GH}`)).match(PLACEHOLDER)?.[0]
  const second = (await store(`echo ${GH} done`)).match(PLACEHOLDER)?.[0]
  expect(first).toBeDefined()
  expect(second).toBe(first)
})

test('an Edit carries the real value to the tool in both strings', async ($, on) => {
  const { store, calls } = await setup($, on)
  const token = (await store(`X=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  await $.tool.call({ tool: 'Edit', file_path: '/repo/config.ts', old_string: `key: '${token}'`, new_string: `key: process.env.GH // ${token}` })
  const edit = calls.at(-1)
  expect(edit?.tool).toBe('Edit')
  expect(edit && 'old_string' in edit ? edit.old_string : '').toBe(`key: '${GH}'`)
  expect(edit && 'new_string' in edit ? edit.new_string : '').toBe(`key: process.env.GH // ${GH}`)
})

test('Bash runs with the real value and its echo, plain or base64, is stored scrubbed', async ($, on) => {
  const { store, calls } = await setup($, on)
  const token = (await store(`export GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  await $.tool.call({ tool: 'Bash', command: `gh secret set GH_TOKEN --body ${token}` })
  const bash = calls.at(-1)
  expect(bash && 'command' in bash ? bash.command : '').toBe(`gh secret set GH_TOKEN --body ${GH}`)

  const echoed = await store(`${GH}\n${btoa(GH)}`)
  expect(echoed).not.toContain(GH)
  expect(echoed).not.toContain(btoa(GH).replace(/=+$/, ''))
  expect(echoed.split('\n')[0]).toBe(token)
  expect(echoed.split('\n')[1]).toMatch(/^<<secret:github-token-b64:[0-9a-f]{12}>>/)
})

test('Read output glyphs for line ends and spaces stay out of the value', async ($, on) => {
  const { store, calls } = await setup($, on)
  const stored = await store(
    `GITHUB_TOKEN=${GH}␊\nDB_URL=postgres://app:` + 'Pw4sd9fk2x' + '@db.local/app␊\nAPI_KEY·=·' + 'Zq81Lm0pRt' + '␊',
  )
  expect(stored).toMatch(/^GITHUB_TOKEN=<<secret:github-token:[0-9a-f]{12}>>␊\n/)
  expect(stored).toContain('@db.local/app␊')
  const placeholders = stored.match(new RegExp(PLACEHOLDER.source, 'g')) ?? []
  expect(placeholders).toHaveLength(3)
  await $.tool.call({ tool: 'Write', file_path: '/repo/out.env', content: placeholders.join('|') })
  const write = calls.at(-1)
  expect(write && 'content' in write ? write.content : '').toBe([GH, 'Pw4sd9fk2x', 'Zq81Lm0pRt'].join('|'))
})

test('a placeholder this session does not know is denied before the tool runs', async ($, on) => {
  const { calls } = await setup($, on)
  const r = await $.tool.call({ tool: 'Bash', command: 'echo <<secret:user:0123456789ab>>' })
  expect(calls).toHaveLength(0)
  expect(r.deny ?? r.text ?? '').toContain('<<secret:user:0123456789ab>>')
})

test('hashes, uuids, plain words and variable references pass untouched', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'commit 9fceb02d0ae598e95dc970b74767f19372d61af8',
    'sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'id: 123e4567-e89b-12d3-a456-426614174000',
    'password: required',
    'token_type: bearer',
    'API_KEY=${API_KEY}',
    'secret = process.env.SECRET_VALUE',
    'const token = getAccessToken(user)',
    'token: ${{ secrets.GH_TOKEN }}',
    'API_KEY=your_api_key_here',
    '"cache_read_input_tokens": 1234567890,',
    'secret_version: 2024-10-22',
    'NEXTAUTH_URL=http://localhost:3000',
    'token_endpoint: https://auth0.example.com/oauth/token',
    'private_key_path: /etc/ssl/private/server1.key',
    'secretName: db-credentials-v2',
    'AUTH_SECRET_FILE=./secrets/auth2.txt',
  ].join('\n')
  expect(await store(text)).toBe(text)
})

test('a private key block is redacted whole', async ($, on) => {
  const { store } = await setup($, on)
  const pem = '-----BEGIN ' + 'RSA PRIVATE KEY-----\n' + 'MIIEow' + 'IBAAKCAQEA7q'.repeat(6) + '\n-----END ' + 'RSA PRIVATE KEY-----'
  const stored = await store(`before\n${pem}\nafter`)
  expect(stored).toMatch(/^before\n<<secret:private-key:[0-9a-f]{12}>>\nafter$/)
})

test('a URL keeps its user and host, only the password is redacted', async ($, on) => {
  const { store } = await setup($, on)
  const stored = await store('DATABASE_URL=postgres://u:' + 'pa55w0rdX' + '@h/db')
  expect(stored).toMatch(/^DATABASE_URL=postgres:\/\/u:<<secret:url-password:[0-9a-f]{12}>>@h\/db$/)
})

test('format and template slots in a URL pass untouched, a percent-encoded password does not', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    `printf 'proxy=http://svc:%s@10.0.0.1:3128\\n' "$p"`,
    'url = "postgres://%(user)s:%(password)s@%(host)s/db"',
    'fmt.Sprintf("amqp://guest:%v@%s:5672/", pw, host)',
    'f"postgres://{user}:{password}@{host}/db"',
    '"redis://app:{0}@cache:6379".format(pw)',
  ].join('\n')
  expect(await store(text)).toBe(text)
  expect(await store('postgres://u:' + 'a%2Fb' + '@h/db')).toMatch(/^postgres:\/\/u:<<secret:url-password:[0-9a-f]{12}>>@h\/db$/)
})

test('a URL password that repeats the user or the scheme is a local default; an empty user still hides the password', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'postgresql://postgres:postgres@localhost:5432/postgres',
    'amqp://guest:guest@localhost:5672/',
    'mysql://root:root@127.0.0.1:3306/app',
    'redis://default:redis@localhost:6379',
  ].join('\n')
  expect(await store(text)).toBe(text)
  expect(await store('redis://:' + 'Zq8Wm3Xk2Pv9' + '@cache:6379')).toMatch(/^redis:\/\/:<<secret:url-password:[0-9a-f]{12}>>@cache:6379$/)
})

test('a key on one line is never paired with the next line', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'auth:',
    '  username: admin',
    'tokens:',
    '  maxLength: 2048',
    'token:',
    '  audience: api-server',
    'env:',
    '  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}',
  ].join('\n')
  expect(await store(text)).toBe(text)
})

test('a key inside a path, a test id or an ARN is left alone, and an assignment after it is still found', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'tests/test_auth.py::test_login_with_valid_credentials PASSED',
    'tests/test_auth.py::TestToken::test_refresh_expired FAILED',
    'src/auth/token.ts:42:export function refreshToken(token: string) {',
    'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf',
  ].join('\n')
  expect(await store(text)).toBe(text)
  const pw = 'Hx7k2mQ9' + 'pL'
  expect(await store(`config/secrets.yml:12:password: ${pw}`)).toMatch(
    /^config\/secrets\.yml:12:password: <<secret:password:[0-9a-f]{12}>>$/,
  )
})

test('types and code on the right of a key are left alone', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'export function parseDir(token: string): Dir {',
    'const fmt = (tokens: number): string => String(tokens)',
    'isSecret: boolean): void',
    'tokens: string[]',
    'auth: Record<string, string>',
    'secret: Optional[str] = None',
    'const tokenValue = tokens[1]',
    'const auth = !req.headers',
  ].join('\n')
  expect(await store(text)).toBe(text)
})

test('a quoted module path, class name, word or phrase is not a password, a quoted password still is', async ($, on) => {
  const { store } = await setup($, on)
  const text = [
    'self.auth_backend = "django.contrib.auth.backends.ModelBackend"',
    'AUTH_USER_MODEL = "accounts.User"',
    '"tokenizer_class": "LlamaTokenizerFast"',
    '"auth": "Required",',
    'auth: Configured',
    'password = input("Password: ")',
    "token: 'Publish token'",
    "read({ prompt: 'npm password: ', silent: true })",
    'tokenData.cidr_whitelist = validCIDR',
    'const authKey = _authKey',
  ].join('\n')
  expect(await store(text)).toBe(text)
  expect(await store('password: "' + 'Summer' + '2024!' + '"')).toMatch(/^password: "<<secret:password:[0-9a-f]{12}>>"$/)
})

test('sk- in a hyphenated name is not an OpenAI key', async ($, on) => {
  const { store } = await setup($, on)
  const text = ['sk-learn-pipeline-module-for-classification', '<div class="sk-circle-bounce-spinner-wrapper-xl">'].join('\n')
  expect(await store(text)).toBe(text)
  expect(await store('sk-' + 'proj-' + 'Zx9Qw3'.repeat(5))).toMatch(/^<<secret:openai-key:[0-9a-f]{12}>>$/)
})

test('a known value never replaces part of a longer word', async ($, on) => {
  const { store } = await setup($, on)
  const pw = 'Pa55' + 'word1'
  await store(`DB_PASSWORD=${pw}`)
  const text = `${pw}23 and x${pw} stay`
  expect(await store(text)).toBe(text)
  expect(await store(`echo "${pw}"`)).toMatch(/^echo "<<secret:password:[0-9a-f]{12}>>"$/)
})

test('a known word joined to a host or a name by a dot or a hyphen stays, a token does not', async ($, on) => {
  const { store } = await setup($, on)
  const word = 'front' + 'desk'
  await store(`postgresql://app:${word}@db:5432/x`)
  for (const text of [`https://${word}.zio.run/api`, `/srv/${word}.zio.run/src`, `Zio-${word}-zio-run`]) {
    expect(await store(text)).toBe(text)
  }
  for (const text of [`PGPASSWORD=${word}`, `the password is ${word}.`]) expect(await store(text)).not.toContain(word)
  const pw = 'Pa55' + 'word1'
  await store(`DB_PASSWORD=${pw}`)
  expect(await store(`https://x.io/${pw}.txt`)).not.toContain(pw)
})

test('plan, todo and local search tools never refuse a placeholder', async ($, on) => {
  const { store, calls } = await setup($, on)
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  for (const input of [
    { tool: 'ExitPlanMode', plan: `1. write ${ph} into .env` },
    { tool: 'TodoWrite', todos: [{ content: `move ${ph} to .env`, status: 'pending' }] },
    { tool: 'TaskCreate', subject: `move ${ph} to .env`, description: 'x' },
    { tool: 'mcp__ccd_turn__update_plan', items: [{ content: `move ${ph}`, status: 'pending' }] },
  ]) {
    const r = await $.tool.call(input as never)
    expect(r.deny).toBeUndefined()
    expect(JSON.stringify(calls.at(-1))).toContain(ph)
  }
  const grep = await $.tool.call({ tool: 'Grep', pattern: ph, path: '/repo' } as never)
  expect(grep.deny).toBeUndefined()
  expect(calls.at(-1)).toMatchObject({ tool: 'Grep', pattern: GH })
})

test('/secret registers a value, fills the prompt, and scrubs it from later rows', async ($, on) => {
  const { store } = await setup($, on)
  const filled: string[] = []
  on('command.register', () => ({ value: { command: 'secret' } }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('prompt.fill', (_, e) => {
    filled.push(e.text)
    return { isFilled: true }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const value = 'correct' + 'horse' + 'battery'
  const r = await $.command.run({
    command: 'secret',
    args: ` ${value} `,
    origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 80 },
  })
  const token = r.text?.match(PLACEHOLDER)?.[0]
  expect(token).toMatch(/^<<secret:user:[0-9a-f]{12}>>$/)
  // In inline code: markdown reads a bare `<secret:…>` as an autolink and drops a bracket of each pair.
  expect(r.text).toBe(`\`${token}\` 로 등록됨`)
  expect(filled).toEqual([`${token} `])

  expect(await store(`the wifi password is ${value}.`)).toBe(`the wifi password is ${token}.`)
})

test('the system prompt gains the policy section', async ($, on) => {
  on('prompt.compose', () => ({ sections: [{ id: 'intro', text: 'hello', scope: 'shared' }] }))
  const r = await $.prompt.compose({ model: 'm', promptModel: 'm', surfaces: [], tools: [], outputStyle: null, traits: [] })
  expect(r.sections.map(s => s.id)).toEqual(['intro', 'secret-guard:policy'])
  expect(r.sections.at(-1)?.text).toContain('<<secret:LABEL:ID>>')
})

test('mentioned files and CLAUDE.md reach the model scrubbed', async ($, on) => {
  mock.store(on)
  on('prompt.attachment', (_, e) => ({ text: e.text }))
  on('prompt.context', (_, e) => ({ blocks: e.blocks }))
  const attached = await $.prompt.attachment({ type: 'file', text: `SLACK=${GH}`, origin: { kind: 'engine' } } as Parameters<Engine['prompt']['attachment']>[0])
  expect(attached.text).toMatch(/^SLACK=<<secret:github-token:[0-9a-f]{12}>>$/)
  const context = await $.prompt.context({ blocks: [{ name: 'claudeMd', text: `deploy token ${GH}` }] })
  expect(context.blocks[0]?.text).toBe(`deploy token ${attached.text?.slice(6)}`)
})

test('placeholder ids are HMAC-SHA256 (RFC 4231 case 2), cut to 12 hex', async () => {
  expect(await idFor('Jefe', 'what do ya want for nothing?')).toBe('5bdcc146bf60')
})

test('a row the guard cannot inspect is stored hidden, not raw', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  on('state.get', () => ({ deny: 'unavailable' }))
  await $.session.append(toolResult(`GITHUB_TOKEN=${GH}`))
  const stored = textOf(session.appended().at(-1))
  expect(stored).toBe(HIDDEN)
})

test('a reply draws its secret paragraphs itself, the value behind a hover, the rest as markdown', async ($, on) => {
  const { store, draw } = await setup($, on)
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const text = `# 결과\n\n- 토큰은 ${ph} 입니다\n\n\`\`\`yaml\ntoken: ${ph}\n\`\`\`\n\n끝.`
  const tree = JSON.stringify(await $.ui.render({ surface: 'desktop', component: 'AssistantMessage', requestId: 'm1', props: { text, isFirstOfReply: true } } as never))
  expect(tree).not.toContain('<<secret:')
  expect(tree).toContain(GH)
  expect(tree).toContain('eye-off')
  expect(tree).toContain('.secret .v,.eye{opacity:0}')
  expect(tree).not.toContain('filter')
  expect(tree).toContain('• 토큰은 ')
  expect(tree).toContain('# 결과')
  expect(tree).toContain('끝.')

  const terminal = JSON.stringify(await $.ui.render({ surface: 'terminal', component: 'AssistantMessage', requestId: 'm2', props: { text, isFirstOfReply: true } } as never))
  expect(terminal).toContain('🙈')
  expect(terminal).toContain(GH)
  expect(terminal).not.toContain('<svg')

  const plain = await draw('AssistantMessage', { text: '비밀 없음', isFirstOfReply: true })
  expect(plain.text).toBe('비밀 없음')
})

const SURFACES = ['desktop', 'terminal', 'vscode', 'mobile'] as const

test('a reply chip copies the real value in one press, the value never in a key or the toast', async ($, on) => {
  const { store } = await setup($, on)
  const copied: string[] = []
  const toasts: string[] = []
  on('ui.copy', (_, e) => {
    copied.push(e.text)
    return { value: { isCopied: true } }
  })
  on('ui.toast', (_, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const unknown = '<<secret:github-token:' + 'afe8c9' + '04c2e6>>'
  const text = `토큰은 ${ph} 이고 옛 값은 ${unknown} 입니다`
  for (const surface of SURFACES) {
    copied.length = 0
    toasts.length = 0
    const ui = await $.ui.mount({ plugin: 'secret-guard', surface, component: 'AssistantMessage', props: { text, isFirstOfReply: true } })
    const buttons = await ui.findAll({ type: 'Button' })
    expect(buttons).toHaveLength(1)
    expect(JSON.stringify(buttons)).not.toContain(GH)
    await ui.press({ key: buttons[0]?.key ?? '' })
    expect(copied).toEqual([GH])
    expect(toasts).toHaveLength(1)
    expect(toasts[0]).toContain('github-token')
    expect(toasts[0]).not.toContain(GH)
    await ui.unmount()
  }
})

test('a copy the surface could not take says so, without the value', async ($, on) => {
  const { store } = await setup($, on)
  const toasts: string[] = []
  on('ui.copy', () => ({ value: { isCopied: false, reason: 'no-clipboard' } }))
  on('ui.toast', (_, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const ui = await $.ui.mount({ plugin: 'secret-guard', surface: 'desktop', component: 'AssistantMessage', props: { text: `토큰은 ${ph}`, isFirstOfReply: true } })
  const [button] = await ui.findAll({ type: 'Button' })
  await ui.press({ key: button?.key ?? '' })
  expect(toasts).toEqual(['복사하지 못했습니다: 이 화면에서는 클립보드를 쓸 수 없습니다'])
  await ui.unmount()
})

test('a user row keeps its own drawing, the value marked and never the note; a pasted placeholder stays as typed', async ($, on) => {
  const { store, draw } = await setup($, on)
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const note = '[secret-guard] Values shaped <<secret:LABEL:ID>> above are redacted credentials. Copy them verbatim into tool inputs; the real value is substituted when the tool runs. Never ask the user for the value or try to recover it.'
  const user = (text: string) => draw('UserMessage', { text, origin: { kind: 'unclassified' }, isExpanded: false })
  for (const text of [`token ${ph}\n\n${note}`, `token ${GH}`]) expect((await user(text)).text).toBe(`token 🙈${GH}`)
  expect((await user(`hello\n\n${note}`)).text).toBe('hello')
  const pasted = '`<<secret:url-password:' + 'afe8c9' + '04c2e6>>_sadfasl`'
  expect((await user(pasted)).text).toBe(pasted)
})

test('a prompt with a secret tells the model beside it, never in the text the person typed', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  const submitted: { text: string; context?: readonly string[] }[] = []
  on('prompt.submit', (_, e) => {
    submitted.push({ text: e.text, context: e.context })
    return { text: e.text, context: e.context }
  })
  await $.prompt.submit({ text: `token ${GH}`, wait: false, origin: { kind: 'composer' } })
  await $.prompt.submit({ text: 'hello there', wait: false, origin: { kind: 'composer' } })
  expect(submitted[0]?.context?.join('\n')).toContain('[secret-guard] Values shaped')
  expect(submitted[1]?.context ?? []).toEqual([])
  await $.session.append({
    message: { type: 'user', role: 'user', content: [{ type: 'text', text: `token ${GH}` }] },
    door: 'prompt',
    origin: { kind: 'composer' },
    uuid: 'prompt-1',
  } as never)
  const typed = String(session.appended().at(-1)?.message.content[0]?.text)
  expect(typed).toMatch(/^token <<secret:github-token:[0-9a-f]{12}>>$/)
})

test('a placeholder written without its brackets is never taken for a secret', async ($, on) => {
  const { store } = await setup($, on)
  const id = 'afe8c9' + '04c2e6'
  for (const text of [`url-password:${id}`, `secret:url-password:${id}`, `(github-token-b64:${id})`]) {
    expect(await store(text)).toBe(text)
  }
})

test('only file and process tools get the real value; network and MCP tools are refused, handoff tools keep the placeholder', async ($, on) => {
  const { store, calls } = await setup($, on)
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const fetched = await $.tool.call({ tool: 'WebFetch', url: `https://example.com/?k=${ph}`, prompt: 'read' } as never)
  expect(fetched.deny ?? fetched.text ?? '').toContain('secret-guard')
  const mcp = await $.tool.call({ tool: 'mcp__slack__post', text: ph } as never)
  expect(mcp.deny ?? mcp.text ?? '').toContain('secret-guard')
  expect(calls).toHaveLength(0)
  await $.tool.call({ tool: 'Agent', prompt: `use ${ph}`, description: 'x', subagent_type: 'general-purpose' } as never)
  expect(JSON.stringify(calls.at(-1))).toContain(ph)
  await $.tool.call({ tool: 'WebFetch', url: 'https://example.com', prompt: 'read' } as never)
  expect(calls).toHaveLength(2)
})

test('hex and uuid secrets, and passwords with shell or quote characters, are redacted whole', async ($, on) => {
  const { store } = await setup($, on)
  const hex = 'ab12'.repeat(16)
  const uuid = '123e4567-e89b-12d3-a456-426614174000'
  const cases = [
    [`JWT_SECRET=${hex}`, hex],
    [`client_secret: ${uuid}`, uuid],
    ['DB_PASSWORD=P@ss$w0rd123', 'P@ss$w0rd123'],
    ['"password": "Ab1(cdefgh)"', 'Ab1(cdefgh)'],
    ['API_KEY=aB3xyz789;tail', 'aB3xyz789'],
    ['API_KEY=Abcdefgh12......', 'Abcdefgh12......'],
  ] as const
  for (const [line, value] of cases) {
    const stored = await store(line)
    expect(stored).not.toContain(value)
    expect(stored).toMatch(PLACEHOLDER)
  }
  const sha = 'cd34'.repeat(10)
  expect(await store(`commit_sha: ${sha}`)).toBe(`commit_sha: ${sha}`)
  expect(await store('API_KEY=sk-xxxxxxxxxxxxxxxx')).toBe('API_KEY=sk-xxxxxxxxxxxxxxxx')
})

test('service tokens, webhook URLs, Basic credentials and Azure account keys are redacted', async ($, on) => {
  const { store } = await setup($, on)
  const run = (n: number) => 'Ab1cD2eF3gH4'.repeat(8).slice(0, n)
  const basic = btoa('admin:' + 'S3cret' + 'Pass99')
  const cases = [
    ['huggingface-cli login ' + 'hf' + '_' + run(34), 'hf' + '_' + run(34)],
    ['key ' + 'SG' + '.' + run(22) + '.' + run(43), 'SG' + '.' + run(22) + '.' + run(43)],
    ['bot ' + '123456789:' + 'AA' + run(33), '123456789:' + 'AA' + run(33)],
    ['oauth client ' + 'GOCSPX' + '-' + run(28), 'GOCSPX' + '-' + run(28)],
    ['doctl auth init -t ' + 'dop' + '_v1_' + 'ab12'.repeat(16), 'dop' + '_v1_' + 'ab12'.repeat(16)],
    ['https://discord.com/api/webhooks/123456789012345678/' + run(68), run(68)],
    ['https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/' + run(24), run(24)],
    ['Authorization: Basic ' + basic, basic],
    ['AccountName=foo;AccountKey=' + run(86) + '==;EndpointSuffix=core.windows.net', run(86) + '=='],
    ['https://api.telegram.org/bot' + '123456789:' + 'AA' + run(33) + '/getMe', '123456789:' + 'AA' + run(33)],
    ['TELEGRAM_BOT_TOKEN=' + '123456789:' + 'AA' + run(32) + '-', '123456789:' + 'AA' + run(32) + '-'],
    ['oauth client ' + 'GOCSPX' + '-' + run(27) + '-', 'GOCSPX' + '-' + run(27) + '-'],
    ['AccountName=foo;AccountKey=/' + run(85) + '==;EndpointSuffix=core.windows.net', '/' + run(85) + '=='],
    ['Authorization: Basic ' + btoa('sk' + '_live_' + run(24) + ':'), btoa('sk' + '_live_' + run(24) + ':')],
    ['Authorization: Basic ' + 'YWRtaW4667mE67CA67KI7Zi4MTIzNA==', 'YWRtaW4667mE67CA67KI7Zi4MTIzNA=='],
    ['https://discord.com/api/v10/webhooks/123456789012345678/' + run(68), run(68)],
    ['git -c http.extraHeader="Authorization: Basic ' + btoa(':' + run(52)) + '"', btoa(':' + run(52))],
    ['Authorization:·Basic·' + basic + '␊', basic],
    ['Authorization:·Bearer·' + run(40) + '␊', run(40)],
  ] as const
  for (const [line, value] of cases) {
    const stored = await store(line)
    expect(stored).not.toContain(value)
    expect(stored).toMatch(PLACEHOLDER)
  }
  const plain = [
    'from huggingface_hub import hf_hub_download',
    'Basic usage: run the tool',
    'Authorization: Basic ' + btoa('no colon in this one'),
    'see https://hooks.slack.com/services for setup',
    'account_key_id: 42',
    'AUTH_CALLBACK=https://example.com/oauth/callback?next=',
    'SECRET_DIR=./secrets/base=',
  ].join('\n')
  expect(await store(plain)).toBe(plain)
})

test('two first rows at once share one salt, so one value keeps one placeholder', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  await Promise.all([$.session.append(toolResult(`A=${GH}`)), $.session.append(toolResult(`B=${GH}`))])
  const ids = session.appended().map(row => textOf(row).match(PLACEHOLDER)?.[2])
  expect(ids[0]).toBeDefined()
  expect(ids[1]).toBe(ids[0])
})

test('a short URL password is hidden in the URL but never marks unrelated text on screen', async ($, on) => {
  const { store, draw } = await setup($, on)
  expect(await store('postgres://u:pw@h/db')).toMatch(/^postgres:\/\/u:<<secret:url-password:[0-9a-f]{12}>>@h\/db$/)
  const result = await draw('ToolResult', { tool_use_id: 't1', tool: 'Bash', output: { stdout: 'pwd is /home', stderr: '' }, isErrored: false })
  expect((result.output as { stdout: string }).stdout).toBe('pwd is /home')
})

test('tool rows show the real value with the mark, in the input and in the raw output', async ($, on) => {
  const { store, draw } = await setup($, on)
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  const use = await draw('ToolUse', {
    tool_use_id: 't1', tool: 'Write', input: { file_path: '/a.yaml', content: `token: ${ph}` },
    isRunning: true, isErrored: false, isInterrupted: false,
  })
  expect((use.input as { content: string }).content).toBe(`token: 🙈${GH}`)
  expect('output' in use).toBe(false)
  const result = await draw('ToolResult', { tool_use_id: 't1', tool: 'Bash', output: { stdout: `GITHUB_TOKEN=${GH}`, stderr: '' }, isErrored: false })
  expect((result.output as { stdout: string }).stdout).toBe(`GITHUB_TOKEN=🙈${GH}`)
})

test('a placeholder copied a little wrong is never wrapped in another', async ($, on) => {
  const { store } = await setup($, on)
  for (const line of ['GITHUB_TOKEN 줄은 `<<secret:github-token:800ca8da1eb7x>>`', 'token <<secret:github-token:800ca8da1eb7>']) {
    expect(await store(line)).toBe(line)
  }
})

test('a request that still carries a known value is sent as is', async ($, on) => {
  const { store } = await setup($, on)
  let conversation = 'nothing yet'
  let sent = 0
  on('session.messages', () => ({ value: [{ role: 'user', content: [{ type: 'text', text: conversation }] }] }) as never)
  on('turn.step', async function* (_, e) {
    sent++
    return { turnId: e.turnId, index: e.index, answer: 'ok', toolUses: [], stopReason: 'end_turn', usage: null }
  })
  const step = async () => {
    const stream = $.turn.step({ turnId: 't', index: 0, model: 'm', messageCount: 1 })
    const chunks = []
    for (let r = await stream.next(); ; r = await stream.next()) {
      if (r.done) return { result: r.value, chunks }
      chunks.push(r.value)
    }
  }
  const ph = (await store(`GITHUB_TOKEN=${GH}`)).match(PLACEHOLDER)?.[0] ?? ''
  conversation = `token ${ph}`
  expect((await step()).result.answer).toBe('ok')
  expect(sent).toBe(1)
  conversation = `[re-read after compaction] GITHUB_TOKEN=${GH}`
  const { result, chunks } = await step()
  expect(sent).toBe(2)
  expect(result.answer).toBe('ok')
  expect(chunks).toEqual([])
})

test('after a resume, a value raw beside its own placeholder is still sent', async ($, on) => {
  const salt = 'ab'.repeat(32)
  mock.store(on, { salt })
  let sent = 0
  const id = await idFor(salt, GH)
  let conversation = `summary: GITHUB_TOKEN=<<secret:github-token:${id}>>`
  on('session.messages', () => ({ value: [{ role: 'user', content: [{ type: 'text', text: conversation }] }] }) as never)
  on('turn.step', async function* (_, e) {
    sent++
    return { turnId: e.turnId, index: e.index, answer: 'ok', toolUses: [], stopReason: 'end_turn', usage: null }
  })
  const step = async () => {
    const stream = $.turn.step({ turnId: 't', index: 0, model: 'm', messageCount: 1 })
    for (let r = await stream.next(); ; r = await stream.next()) if (r.done) return r.value
  }
  expect((await step()).answer).toBe('ok')
  conversation += `\n\nre-read: GITHUB_TOKEN=${GH}\nOTHER_TOKEN=${'gh' + 'p_' + 'Z9y8'.repeat(9)}`
  expect((await step()).answer).toBe('ok')
  expect(sent).toBe(2)
})

// A stored row (note included) as the next request carries it.
async function guardedStep($: Engine, on: On, conversation: () => string) {
  let sent = 0
  on('session.messages', () => ({ value: [{ role: 'user', content: [{ type: 'text', text: conversation() }] }] }) as never)
  on('turn.step', async function* (_, e) {
    sent++
    return { turnId: e.turnId, index: e.index, answer: 'ok', toolUses: [], stopReason: 'end_turn', usage: null }
  })
  return async () => {
    const stream = $.turn.step({ turnId: 't', index: 0, model: 'm', messageCount: 1 })
    for (let r = await stream.next(); ; r = await stream.next()) if (r.done) return { answer: r.value.answer, sent }
  }
}

const storedRow = (row: SessionAppendInput | undefined) =>
  (row?.message.content ?? [])
    .map(b => (b.type === 'tool_result' ? JSON.stringify(b.content) : b.type === 'text' ? String(b.text) : ''))
    .join('\n')

test('the placeholder notation in docs and in the guard note is never taken for a secret', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  let stored = ''
  const step = await guardedStep($, on, () => stored)
  const doc = '모델은 실제 값 대신 `<<secret:LABEL:ID>>` 자리표시자를 봅니다.'
  await $.session.append(toolResult(`${doc}\nGITHUB_TOKEN=${GH}`))
  stored = storedRow(session.appended().at(-1))
  expect(stored).toContain(doc)
  expect(stored).toContain('[secret-guard] Values shaped <<secret:LABEL:ID>>')
  expect(await step()).toEqual({ answer: 'ok', sent: 1 })
})

test('a value found once is hidden wherever else it shows in the same result', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  let stored = ''
  const step = await guardedStep($, on, () => stored)
  const pw = 'Pw9xQ2' + 'mZ7kLb'
  await $.session.append(toolResult(`proxy=http://svc:${pw}@10.0.0.1:3128\nproxyauth ${pw} --setenv`))
  stored = storedRow(session.appended().at(-1))
  expect(stored).not.toContain(pw)
  expect(await step()).toEqual({ answer: 'ok', sent: 1 })
})

test('a value found in a later block of a row is hidden in the earlier blocks too', async ($, on) => {
  const session = mock.session(on)
  mock.store(on)
  let stored = ''
  const step = await guardedStep($, on, () => stored)
  const pw = 'Qa7wE3' + 'rT9yUi'
  await $.session.append({
    ...toolResult(''),
    message: {
      type: 'user',
      role: 'user',
      content: [
        {
          type: 'tool_result',
          tool_use_id: 'tu-blocks',
          content: [
            { type: 'text', text: `first: proxyauth ${pw}` },
            { type: 'text', text: `second: http://svc:${pw}@db.internal:5432` },
          ],
        },
      ],
    },
  })
  stored = storedRow(session.appended().at(-1))
  expect(stored).not.toContain(pw)
  expect(await step()).toEqual({ answer: 'ok', sent: 1 })
})
