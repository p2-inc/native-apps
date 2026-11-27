/** base64url, UTF-8 and SHA-256 helpers over WebCrypto. */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function fromUtf8(bytes: ArrayBuffer | Uint8Array): string {
  return decoder.decode(bytes);
}

/** base64url without padding. */
export function base64UrlEncode(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url (padding optional); `undefined` when the input is not base64url. */
export function base64UrlDecode(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) return undefined;
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return undefined;
  }
}

/** A `BufferSource` WebCrypto and WebAuthn accept everywhere (TypeScript 5.7+ narrows `Uint8Array`). */
export function bufferSource(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer;
}

export function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (s === undefined) {
    throw new Error(
      'WebCrypto is unavailable: the web SDK needs a secure context (https or localhost)'
    );
  }
  return s;
}

export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await subtle().digest('SHA-256', bufferSource(bytes)));
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function randomId(): string {
  return globalThis.crypto.randomUUID();
}

/** The unverified payload of a JWT, for display only (resource servers validate tokens). */
export function decodeJwtPayload(
  jwt: string | undefined
): Record<string, unknown> | undefined {
  const part = jwt?.split('.')[1];
  if (part === undefined) return undefined;
  const bytes = base64UrlDecode(part);
  if (bytes === undefined) return undefined;
  try {
    const value: unknown = JSON.parse(fromUtf8(bytes));
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}
