// HOTP (RFC 4226) and TOTP (RFC 6238) for the Clavium Authenticator.
//
// This is an independent reimplementation of the same algorithm as
// `clavium_security_core::otp` (Rust, used by the desktop app) rather
// than a shared library — React Native has no practical bridge to the
// Rust core without a much larger native-module build pipeline (uniffi,
// per-platform Xcode/Android Studio toolchains this environment can't
// run), and the plan's own Milestone 4 description anticipates
// TypeScript for this app. Correctness is anchored the same way the
// Rust engine's tests are: RFC 4226 Appendix D's own published HOTP
// vectors, not a second, independently-recalled set of TOTP decimals.
//
// HMAC comes from `jssha` — pure JavaScript, no native module, so this
// runs unmodified in Expo Go on a real phone, not just a custom dev
// build.

import jsSHA from "jssha";

export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpParams {
  secret: Uint8Array;
  algorithm: OtpAlgorithm;
  digits: number;
  periodSeconds: number;
}

export function defaultParams(secret: Uint8Array): TotpParams {
  return { secret, algorithm: "SHA1", digits: 6, periodSeconds: 30 };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function counterToHex(counter: number): string {
  // RFC 4226's counter is a full 8-byte big-endian integer. `counter`
  // here is always time/30, which won't approach Number.MAX_SAFE_INTEGER
  // for a very long time, so splitting into two 32-bit halves is exact.
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  return high.toString(16).padStart(8, "0") + low.toString(16).padStart(8, "0");
}

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytes;
}

/** RFC 4226's dynamic truncation (§5.3), applied to a raw HMAC digest.
 * Works on the hex string directly — no `Buffer`, which React Native's
 * JS runtime (Hermes) doesn't provide without a Node polyfill this app
 * has no other reason to carry. */
function truncate(digestHex: string, digits: number): string {
  const digest = hexToBytes(digestHex);
  const offset = digest[digest.length - 1] & 0x0f;
  const code =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  const modulus = 10 ** digits;
  return String(code % modulus).padStart(digits, "0");
}

export function hotp(secret: Uint8Array, counter: number, algorithm: OtpAlgorithm, digits: number): string {
  const shaVariant = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }[algorithm] as
    | "SHA-1"
    | "SHA-256"
    | "SHA-512";
  const hmac = new jsSHA(shaVariant, "HEX", { hmacKey: { value: toHex(secret), format: "HEX" } });
  hmac.update(counterToHex(counter));
  return truncate(hmac.getHMAC("HEX"), digits);
}

export function totpAt(params: TotpParams, unixSeconds: number): string {
  const counter = Math.floor(unixSeconds / params.periodSeconds);
  return hotp(params.secret, counter, params.algorithm, params.digits);
}

export function totpNow(params: TotpParams): string {
  return totpAt(params, Math.floor(Date.now() / 1000));
}

export function secondsRemaining(params: TotpParams, unixSeconds: number): number {
  return params.periodSeconds - (unixSeconds % params.periodSeconds);
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 Base32 decode — same reasoning as the Rust version for
 * hand-rolling this rather than adding a dependency: it's ~20 lines and
 * this crosses no security boundary (it's a correctness utility, not a
 * secret-handling one). */
export function base32Decode(input: string): Uint8Array {
  const cleaned = input.replace(/\s+/g, "").replace(/=+$/, "").toUpperCase();
  const out: number[] = [];
  let bits = 0;
  let bitCount = 0;

  for (const char of cleaned) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`invalid Base32 character: ${char}`);
    }
    bits = (bits << 5) | value;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      out.push((bits >> bitCount) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function percentDecode(input: string): string {
  try {
    return decodeURIComponent(input);
  } catch {
    return input;
  }
}

/** Parse a scanned `otpauth://totp/...` URI. Defaults (SHA1, 6 digits,
 * 30s) match every major issuer's own assumption when a parameter is
 * left out. */
export function parseOtpauthUri(uri: string): { label: string; params: TotpParams } {
  const prefix = "otpauth://totp/";
  if (!uri.startsWith(prefix)) {
    throw new Error("not an otpauth://totp/ URI");
  }
  const rest = uri.slice(prefix.length);
  const queryIndex = rest.indexOf("?");
  if (queryIndex === -1) {
    throw new Error("otpauth URI has no query parameters");
  }
  const label = percentDecode(rest.slice(0, queryIndex));
  const query = new URLSearchParams(rest.slice(queryIndex + 1));

  const secretParam = query.get("secret");
  if (!secretParam) {
    throw new Error("otpauth URI has no secret parameter");
  }

  const algorithmParam = (query.get("algorithm") ?? "SHA1").toUpperCase();
  const algorithm: OtpAlgorithm =
    algorithmParam === "SHA256" ? "SHA256" : algorithmParam === "SHA512" ? "SHA512" : "SHA1";

  const params: TotpParams = {
    secret: base32Decode(secretParam),
    algorithm,
    digits: Number(query.get("digits") ?? "6"),
    periodSeconds: Number(query.get("period") ?? "30"),
  };
  return { label, params };
}

/** Accepts either a full otpauth:// URI or a bare Base32 secret — what a
 * real enrollment screen hands someone, scannable or not. */
export function parseSecretOrUri(input: string): TotpParams {
  const trimmed = input.trim();
  if (trimmed.startsWith("otpauth://")) {
    return parseOtpauthUri(trimmed).params;
  }
  return defaultParams(base32Decode(trimmed));
}
