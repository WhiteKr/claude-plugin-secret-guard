import type { EngineInterface, RenderElement, RenderInput, RenderSurface } from 'claude-code'

import { ICON as HIDDEN, ICON_SHOWN as SHOWN } from './display'
import type { Part, Piece } from './display'

// On the terminal, which draws no SVG, the value is drawn in its own
// background color, a bar no one can read, until the pointer rests on it.
const BAR = 'subtle'

const escapeXml = (text: string) =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const CHAR_WIDTH = 7.25
const HEIGHT = 20

// Claude Desktop's palette: warm gray at rest, its clay orange under the pointer.
const MUTED = '#8f8a83'
const CLAY = '#d97757'

// Line icons in the app's style (24-unit paths, drawn at 14px).
const EYE_OFF =
  '<path d="M10.7 5.1a10.7 10.7 0 0 1 11.2 6.6 1 1 0 0 1 0 .7 10.7 10.7 0 0 1-1.4 2.5"/><path d="M14.1 14.2a3 3 0 0 1-4.3-4.3"/><path d="M17.5 17.5a10.7 10.7 0 0 1-15.4-5.2 1 1 0 0 1 0-.7 10.7 10.7 0 0 1 4.4-5.1"/><path d="m2 2 20 20"/>'
const EYE = '<path d="M2.1 12.3a1 1 0 0 1 0-.7 10.7 10.7 0 0 1 19.8 0 1 1 0 0 1 0 .7 10.7 10.7 0 0 1-19.8 0"/><circle cx="12" cy="12" r="3"/>'

// The resting chip never holds the value: the desktop strips SVG filters, so
// the blur is faked by stacking offset copies of filler text of the same
// length, and the real text stays at opacity 0 until the pointer rests on it.
const SMEAR: readonly [number, number][] = [[-2, 0], [2, 0], [0, -1], [0, 1], [-1, 1], [1, -1], [-3, 0], [3, 0]]
const FILLER = 'k7Rx2QmZp9Lw4VbN8tYc3HsJ6dGf5aEu'
const filler = (length: number) => FILLER.repeat(Math.ceil(length / FILLER.length)).slice(0, length)

export function pillSvg(text: string, isSecret: boolean): { source: string; width: number } {
  const span = text.length * CHAR_WIDTH
  const width = Math.ceil(28 + span + 10)
  // Fonts differ by surface (Menlo on a Mac, DejaVu or Ubuntu Mono on Linux); the text is spread to the chip it was measured for.
  // Wide glyphs (Hangul, emoji) and spaces SVG collapses would be squeezed or stretched, so only one-cell text is fitted.
  const fit = /^[!-~]+$/.test(text) ? `textLength="${span.toFixed(1)}" lengthAdjust="spacing"` : ''
  const font = 'font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'
  const smear = SMEAR.map(([dx, dy]) => `<text class="smear" x="${28 + dx}" y="${14 + dy}" ${fit}>${filler(text.length)}</text>`).join('')
  const source = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${HEIGHT}" viewBox="0 0 ${width} ${HEIGHT}">
<style>
.chip{fill:rgba(143,138,131,.12);stroke:rgba(143,138,131,.32);stroke-width:.75;transition:all .12s}
.icon{fill:none;stroke:${MUTED};stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:opacity .12s}
.v{${font};fill:${MUTED}}
.smear{${font};fill:${MUTED};opacity:.16}
.secret .v,.eye{opacity:0}
svg:hover .secret .chip{fill:rgba(217,119,87,.08);stroke:rgba(217,119,87,.55)}
svg:hover .secret .v{opacity:1;fill:${CLAY}}
svg:hover .secret .smear,svg:hover .secret .eye-off{opacity:0}
svg:hover .secret .eye{opacity:1;stroke:${CLAY}}
</style>
<g class="${isSecret ? 'secret' : ''}">
<rect class="chip" x="0.5" y="0.5" rx="6" width="${width - 1}" height="${HEIGHT - 1}"/>
<g transform="translate(8 3) scale(.583)"><g class="icon eye-off">${EYE_OFF}</g><g class="icon eye">${EYE}</g></g>
${isSecret ? smear : ''}
<text class="v" x="28" y="14" ${fit}>${escapeXml(text)}</text>
</g>
</svg>`
  return { source, width }
}

const COPY = '📋'

const COPY_FAILED = {
  'no-surface': '복사할 화면이 연결되어 있지 않습니다',
  'no-clipboard': '이 화면에서는 클립보드를 쓸 수 없습니다',
  refused: '복사가 거부되었습니다',
} as const

async function copy($: EngineInterface, secret: { label: string; value: string }, surface: RenderSurface) {
  const copied = await $.ui.copy({ text: secret.value, surface })
  $.ui.toast(copied.isCopied ? `${secret.label} 값을 클립보드에 복사했습니다` : `복사하지 못했습니다: ${COPY_FAILED[copied.reason]}`)
}

/** A message whose paragraphs holding a secret this mod draws, so a hover can reveal the value. */
export function drawMessage(
  $: EngineInterface,
  e: RenderInput<'AssistantMessage'>,
  parts: Part[],
): RenderElement {
  const table = $.ui.resolve(e)
  const { Box, Text, Markdown, Button } = table
  // The terminal's table answers `Svg` with an element that draws nothing.
  const Svg = e.surface !== 'terminal' && 'Svg' in table ? table.Svg : undefined
  let chips = 0

  const chip = (secret: { label: string; value?: string }) => {
    const n = chips++
    const key = `secret-guard-${e.requestId}-${n}`
    const { label, value } = secret
    // The key and label are what a surface shows or reports, so they never hold the value.
    const copyButton =
      value === undefined ? null : (
        <Button
          key={`secret-guard-copy-${e.requestId}-${n}`}
          label={COPY}
          plain
          dimColor
          hover={{ dimColor: false }}
          onPress={press => void copy($, { label, value }, press.surface)}
        />
      )
    if (Svg) {
      const pill = pillSvg(value ?? label, value !== undefined)
      return (
        <Box key={key} flexDirection="row" flexGrow={0} flexShrink={0}>
          <Svg source={pill.source} alt={`${HIDDEN} ${label}`} width={pill.width} height={HEIGHT} isInteractive />
          {copyButton}
        </Box>
      )
    }
    if (value === undefined) {
      return (
        <Box key={key} flexGrow={0} flexShrink={0}>
          <Text dimColor>{`${HIDDEN} ${label}`}</Text>
        </Box>
      )
    }
    // The monkey covers the hidden-eyes glyph on hover, so it needs a paint of its own.
    return (
      <Box key={key} position="relative" flexDirection="row" flexGrow={0} flexShrink={0}>
        <Text>{`${HIDDEN} `}</Text>
        <Text color={BAR} backgroundColor={BAR} hover={{ color: 'text', backgroundColor: 'transparent' }}>
          {value}
        </Text>
        <Box position="absolute" top={0} left={0} display="none" hover={{ display: 'flex' }} backgroundColor={BAR}>
          <Text>{SHOWN}</Text>
        </Box>
        {copyButton}
      </Box>
    )
  }

  const line = (pieces: Piece[], isCode: boolean, at: string) => (
    <Box key={at} flexDirection="row" flexWrap="wrap">
      {pieces.map((piece, i) =>
        'secret' in piece ? chip(piece.secret) : <Text key={`${at}-${i}`} mono={isCode}>{piece.text}</Text>,
      )}
    </Box>
  )

  return (
    <Box flexDirection="column">
      {parts.map((part, p) =>
        part.kind === 'markdown' ? (
          <Markdown key={`md-${p}`} text={part.text} />
        ) : (
          <Box key={`lines-${p}`} flexDirection="column">
            {part.lines.map((pieces, l) => line(pieces, part.isCode, `line-${p}-${l}`))}
          </Box>
        ),
      )}
    </Box>
  )
}
