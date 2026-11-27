/** JSON values and the lenient readers the model uses (unknown fields are ignored, spec/03 §10). */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export function asObject(value: unknown): JsonObject | undefined {
  return value !== null &&
    value !== undefined &&
    typeof value === 'object' &&
    !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

export function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

export function bool(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

export function num(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value
    : undefined;
}

/** Integers only, like the native SDKs' `intValue`. */
export function int(value: unknown): number | undefined {
  const n = num(value);
  return n !== undefined && Number.isInteger(n) ? n : undefined;
}

export function arr(value: unknown): JsonValue[] {
  return Array.isArray(value) ? (value as JsonValue[]) : [];
}

export function strings(value: unknown): string[] {
  return arr(value).filter((v): v is string => typeof v === 'string');
}

/** The protocol sends instants as seconds since the epoch; the model uses milliseconds. */
export function epochMillis(value: unknown): number | undefined {
  const n = num(value);
  return n === undefined ? undefined : Math.round(n * 1000);
}

/** Parses JSON text, `undefined` when it is not JSON. */
export function parseJson(text: string | undefined): JsonValue | undefined {
  if (text === undefined || text.length === 0) return undefined;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return undefined;
  }
}
