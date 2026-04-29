/**
 * HaveIBeenPwned k-anonymity check.
 * We SHA-1 the password client-side, send only the first 5 hex chars to the API,
 * and search the returned suffix list locally. The full password never leaves the browser.
 */

async function sha1Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-1", enc);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export interface HibpResult {
  pwned: boolean;
  count: number;
}

export async function checkHibp(password: string, signal?: AbortSignal): Promise<HibpResult> {
  if (!password) return { pwned: false, count: 0 };
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },
    signal,
  });
  if (!res.ok) throw new Error(`HIBP request failed: ${res.status}`);
  const text = await res.text();
  for (const line of text.split("\n")) {
    const [suf, countStr] = line.trim().split(":");
    if (suf === suffix) {
      const count = parseInt(countStr, 10) || 0;
      if (count > 0) return { pwned: true, count };
    }
  }
  return { pwned: false, count: 0 };
}
