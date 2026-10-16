// Standalone proof harness — run with `npx tsx src/otp.verify.ts`. Mirrors
// the Rust engine's own test anchors: RFC 4226 Appendix D's published
// HOTP vectors, then TOTP checked structurally against those same
// vectors via the time-to-counter derivation, rather than a second,
// independently-recalled set of TOTP decimals.

import { base32Decode, hotp, parseOtpauthUri, secondsRemaining, totpAt } from "./otp";

let passed = 0;
let failed = 0;
function check(label: string, cond: boolean) {
  if (cond) {
    console.log(`PASS  ${label}`);
    passed++;
  } else {
    console.log(`FAIL  ${label}`);
    failed++;
  }
}

const SECRET = new TextEncoder().encode("12345678901234567890");
const RFC4226_VECTORS: [number, string][] = [
  [0, "755224"],
  [1, "287082"],
  [2, "359152"],
  [3, "969429"],
  [4, "338314"],
  [5, "254676"],
  [6, "287922"],
  [7, "162583"],
  [8, "399871"],
  [9, "520489"],
];

for (const [counter, expected] of RFC4226_VECTORS) {
  check(`hotp counter ${counter}`, hotp(SECRET, counter, "SHA1", 6) === expected);
}

const params = { secret: SECRET, algorithm: "SHA1" as const, digits: 6, periodSeconds: 30 };
check("totp(0) == hotp(0)", totpAt(params, 0) === "755224");
check("totp(29) == hotp(0)", totpAt(params, 29) === "755224");
check("totp(30) == hotp(1)", totpAt(params, 30) === "287082");
check("totp(59) == hotp(1)", totpAt(params, 59) === "287082");
check("totp(60) == hotp(2)", totpAt(params, 60) === "359152");

check("secondsRemaining(0) == 30", secondsRemaining(params, 0) === 30);
check("secondsRemaining(29) == 1", secondsRemaining(params, 29) === 1);

check(
  "base32Decode round-trips a known value",
  Array.from(base32Decode("JBSWY3DPEE======")).join(",") ===
    Array.from(new TextEncoder().encode("Hello!")).join(","),
);

const parsed = parseOtpauthUri(
  "otpauth://totp/Clavium:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Clavium&algorithm=SHA1&digits=6&period=30",
);
check("parseOtpauthUri label", parsed.label === "Clavium:alice@example.com");
check("parseOtpauthUri digits", parsed.params.digits === 6);
check("parseOtpauthUri period", parsed.params.periodSeconds === 30);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
