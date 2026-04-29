/**
 * Email breach lookup — calls our edge function proxy which fetches from
 * the free XposedOrNot API. The proxy is needed because XposedOrNot does
 * not return CORS headers for browser-origin requests.
 *
 * Important: NO legitimate API exposes actual leaked password values —
 * only the data classes/types that were exposed in each breach.
 */


export interface BreachDetail {
  breachID: string;
  breachedDate: string;
  addedDate: string;
  domain: string;
  industry: string;
  logo: string;
  passwordRisk: string;
  searchable: boolean;
  sensitive: boolean;
  verified: boolean;
  exposedData: string[];
  exposedRecords: number;
  exposureDescription: string;
  referenceURL?: string;
}

export interface BreachAnalytics {
  riskLabel: string;
  riskScore: number;
  yearwise: Record<string, number>;
  passwordStrength: { EasyToCrack: number; PlainText: number; StrongHash: number; Unknown: number } | null;
  exposedDataCategories: Array<{ category: string; items: Array<{ name: string; value: number; group: string }> }>;
  breachNames: string[];
}

export interface EmailBreachReport {
  email: string;
  pwned: boolean;
  totalBreaches: number;
  analytics: BreachAnalytics | null;
  breaches: BreachDetail[];
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export function isValidEmail(e: string): boolean {
  return EMAIL_RE.test(e.trim()) && e.length <= 254;
}

export async function checkEmailBreaches(email: string, signal?: AbortSignal): Promise<EmailBreachReport> {
  const e = email.trim().toLowerCase();
  if (!isValidEmail(e)) throw new Error("Invalid email address");

  const url = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/email-breach-lookup?email=${encodeURIComponent(e)}`;
  const res = await fetch(url, {
    signal,
    headers: {
      apikey: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
      Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    let msg = `Lookup failed (${res.status})`;
    try { const j = JSON.parse(body); if (j.error) msg = j.error; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return res.json() as Promise<EmailBreachReport>;
}
