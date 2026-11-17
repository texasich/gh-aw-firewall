import { Transform, TransformCallback } from 'stream';

const MAX_PENDING_CHARS = 32 * 1024;
const OVERLAP_CHARS = 8 * 1024;
const PREFIX_TAIL_WINDOW_CHARS = 16 * 1024;
const CREDENTIAL_PREFIXES = ['github_pat_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'eyJ'];

const CREDENTIAL_PATTERNS = [
  /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])/g,
];

function trailingCredentialPrefixStart(value: string, safeLength: number): number {
  const windowStart = Math.max(0, safeLength - PREFIX_TAIL_WINDOW_CHARS);
  const windowText = value.slice(windowStart, safeLength);

  // Hold back any in-progress JWT or GitHub token that crosses safeLength.
  const jwtIdx = windowText.lastIndexOf('eyJ');
  if (
    jwtIdx >= 0 &&
    (jwtIdx === 0 || !/\w/.test(windowText[jwtIdx - 1])) &&
    /^[A-Za-z0-9_.-]*$/.test(windowText.slice(jwtIdx))
  ) {
    return windowStart + jwtIdx;
  }

  let wordStart = safeLength;
  while (wordStart > windowStart && /\w/.test(value[wordStart - 1])) {
    wordStart -= 1;
  }
  const trailingWord = value.slice(wordStart, safeLength);
  if (
    trailingWord.length > 0 &&
    (/^(?:gh[pousr]|github_pat)_/.test(trailingWord) ||
      CREDENTIAL_PREFIXES.some((prefix) => prefix.startsWith(trailingWord)))
  ) {
    return wordStart;
  }
  return safeLength;
}

function fixedLengthMask(value: string): string {
  const marker = '[REDACTED_CREDENTIAL]';
  return (marker + '*'.repeat(Math.max(0, value.length - marker.length))).slice(0, value.length);
}

export function redactCredentials(value: string): { output: string; detected: boolean } {
  let detected = false;
  let output = value;
  for (const pattern of CREDENTIAL_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, (match) => {
      detected = true;
      return fixedLengthMask(match);
    });
  }
  return { output, detected };
}

export class CredentialRedactingStream extends Transform {
  private pending = Buffer.alloc(0);
  private reported = false;

  constructor(private readonly onCredentialDetected: () => void) {
    super();
  }

  private sanitize(value: Buffer): Buffer {
    const result = redactCredentials(value.toString('latin1'));
    if (result.detected && !this.reported) {
      this.reported = true;
      this.onCredentialDetected();
    }
    return Buffer.from(result.output, 'latin1');
  }

  private safeEmissionLength(emitLength: number): number {
    const value = this.pending.toString('latin1');
    let safeLength = emitLength;
    for (const pattern of CREDENTIAL_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(value)) !== null) {
        const matchEnd = match.index + match[0].length;
        if (match.index < safeLength && matchEnd > safeLength) {
          safeLength = match.index;
        }
      }
    }
    return trailingCredentialPrefixStart(value, safeLength);
  }

  override _transform(chunk: Buffer | string, encoding: BufferEncoding, callback: TransformCallback): void {
    this.pending = Buffer.concat([
      this.pending,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding),
    ]);

    let newlineIndex = this.pending.indexOf(0x0a);
    while (newlineIndex >= 0) {
      const line = this.pending.subarray(0, newlineIndex + 1);
      this.pending = this.pending.subarray(newlineIndex + 1);
      this.push(this.sanitize(line));
      newlineIndex = this.pending.indexOf(0x0a);
    }

    if (this.pending.length > MAX_PENDING_CHARS) {
      const emitLength = this.safeEmissionLength(this.pending.length - OVERLAP_CHARS);
      if (emitLength > 0) {
        this.push(this.sanitize(this.pending.subarray(0, emitLength)));
        this.pending = this.pending.subarray(emitLength);
      }
    }

    callback();
  }

  override _flush(callback: TransformCallback): void {
    if (this.pending.length > 0) {
      this.push(this.sanitize(this.pending));
      this.pending = Buffer.alloc(0);
    }
    callback();
  }
}
