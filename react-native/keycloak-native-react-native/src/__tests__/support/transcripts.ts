import * as fs from 'fs';
import * as path from 'path';
import type { JsonObject, JsonValue } from '../../model';

/**
 * The server's recorded wire transcripts (keycloak-native-auth/demo/transcripts), read in place like
 * the Swift and Kotlin harnesses do, so a re-recorded transcript fails all three clients the same way.
 */
export const TRANSCRIPTS_DIR = path.resolve(
  __dirname,
  '../../../../../keycloak-native-auth/demo/transcripts'
);

export interface Exchange {
  seq: number;
  request: {
    method: string;
    path: string;
    form?: Record<string, string>;
    json?: JsonValue;
  };
  response: { status: number; json?: JsonValue };
}

export interface Transcript {
  test: string;
  masked_form_fields: string[];
  exchanges: Exchange[];
}

export function transcriptNames(): string[] {
  return fs
    .readdirSync(TRANSCRIPTS_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''))
    .sort();
}

export function loadTranscript(name: string): Transcript {
  return JSON.parse(
    fs.readFileSync(path.join(TRANSCRIPTS_DIR, `${name}.json`), 'utf8')
  ) as Transcript;
}

export const isChallengeEndpoint = (e: Exchange) =>
  e.request.path.endsWith('/native-auth/challenge');

export const isTokenEndpoint = (e: Exchange) =>
  e.request.path.endsWith('/protocol/openid-connect/token');

/** The challenge sets (`403 insufficient_authorization` bodies) of the challenge endpoint. */
export function challengeSets(t: Transcript): JsonObject[] {
  return t.exchanges.flatMap((e) => {
    const body = e.response.json;
    return isChallengeEndpoint(e) &&
      body !== null &&
      typeof body === 'object' &&
      !Array.isArray(body) &&
      Array.isArray(body.challenges)
      ? [body]
      : [];
  });
}
