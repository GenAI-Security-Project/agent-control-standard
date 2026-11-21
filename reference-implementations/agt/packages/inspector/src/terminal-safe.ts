/**
 * Makes a string from a log safe to write to an operator's terminal.
 *
 * The logs this package tails hold values a request author chose: the
 * Guardian records an envelope's `method` and `id` before it validates them,
 * and it is unauthenticated. JSON escapes control characters on disk, but the
 * log is parsed before it is rendered, so a field arrives here as the raw
 * characters again. Written to a terminal as they are, an ESC byte starts a
 * sequence the terminal obeys -- clear the screen, move the cursor over the
 * DENY line, retitle the window, write the clipboard -- and a C1 control
 * (U+0080-U+009F) does the same on terminals that decode it.
 *
 * Each such character is replaced by a visible `\xNN` escape instead of being
 * dropped, so an operator reading a line can still see that something was
 * there. The set matches `[\x00-\x1f\x7f-\x9f]`, which covers every C0
 * control, DEL, and every C1 control, and therefore the introducers of CSI,
 * OSC, DCS and the other escape sequences. What remains of a sequence, such
 * as `[2J`, is printable text and does nothing.
 *
 * This is applied to a field before the renderer paints it, never to the
 * painted result, so the Inspector's own ANSI styling is left intact.
 *
 * It does not touch printable characters, so it does not address bidirectional
 * overrides or other Unicode that renders confusingly without being a control.
 */

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/g;
const CONTROL_CHARACTERS_EXCEPT_NEWLINE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g;

function escapeCharacter(character: string): string {
  return `\\x${character.charCodeAt(0).toString(16).padStart(2, "0")}`;
}

/** Escapes every control character in `value`, newlines included, so the
 * result is guaranteed to stay on one line. Use for a single field. */
export function escapeControlCharacters(value: unknown): string {
  return String(value).replace(CONTROL_CHARACTERS, escapeCharacter);
}

/** Like `escapeControlCharacters`, but leaves `\n` alone. Use for text whose
 * line structure the renderer itself produced, such as pretty-printed JSON:
 * `JSON.stringify` escapes C0 controls inside strings, but not DEL or C1. */
export function escapeControlCharactersKeepingNewlines(value: string): string {
  return value.replace(CONTROL_CHARACTERS_EXCEPT_NEWLINE, escapeCharacter);
}
