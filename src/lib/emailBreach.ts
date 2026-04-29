/**
 * XposedOrNot — free, no-key public breach lookup API.
 * Privacy: email is sent only to api.xposedornot.com over HTTPS to query
 * publicly-known breach records. No password ever sent.
 *
 * Important: NO legitimate API exposes actual leaked password values —
 * only the data classes/types that were exposed in each breach.
 */

const BASE = "https://api.xposedornot.com/v1";

export interface BreachDetail {
  breachID: string;
  breachedDate: string;     // ISO
  addedDate: string;
  domain: string;
  industry: string;
  logo: string;
  passwordRisk: string;     // e.g. "easytocrack" | "plaintext" | "stronghash" | "unknown"
  searchable: boolean;
  sensitive: boolean;
  verified: boolean;
  exposedData: string[];    // e.g. ["Email addresses", "Passwords", ...]
  exposedRecords: number;
  exposureDescription: string;
  referenceURL?: string;
}

export interface BreachAnalytics {
  riskLabel: string;          // e.g. "Critical", "High", "Medium", "Low"
  riskScore: number;          // 0..100
  yearwise: Record<string, number>;  // e.g. { "2019": 25, ... }
  passwordStrength: { EasyToCrack: number; PlainText: number; StrongHash: number; Unknown: number } | null;
  exposedDataCategories: Array<{ category: string; items: Array<{ name: string; value: number; group: string }> }>;
  breachNames: string[];      // ordered names from BreachesSummary.site
}

export interface EmailBreachReport {
  email: string;
  pwned: boolean;
  totalBreaches: number;
  analytics: BreachAnalytics | null;
  breaches: BreachDetail[];
}

interface XonCheckEmailResp {
  breaches?: string[][];
  Error?: string;
}

interface XonAnalyticsResp {
  BreachMetrics?: {
    risk?: Array<{ risk_label: string; risk_score: number }>;
    yearwise_details?: Array<Record<string, number>>;
    passwords_strength?: Array<{ EasyToCrack: number; PlainText: number; StrongHash: number; Unknown: number }>;
    xposed_data?: Array<{
      children: Array<{
        name: string;
        children: Array<{ name: string; value: number; group: string }>;
      }>;
    }>;
  };
  BreachesSummary?: { site: string };
  Error?: string;
}

interface XonBreachInfoResp {
  exposedBreaches?: BreachDetail[];
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export function isValidEmail(e: string): boolean {
  return EMAIL_RE.test(e.trim()) && e.length <= 254;
}

async function fetchJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal, headers: { accept: "application/json" } });
  if (!res.ok && res.status !== 404) {
    throw new Error(`Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function checkEmailBreaches(
  email: string,
  signal?: AbortSignal,
): Promise<EmailBreachReport> {
  const e = email.trim().toLowerCase();
  if (!isValidEmail(e)) throw new Error("Invalid email address");

  const enc = encodeURIComponent(e);

  const [check, analytics] = await Promise.all([
    fetchJson<XonCheckEmailResp>(`${BASE}/check-email/${enc}`, signal),
    fetchJson<XonAnalyticsResp>(`${BASE}/breach-analytics?email=${enc}`, signal),
  ]);

  // Not found → no breaches
  const breachNamesRaw = check.breaches?.[0] ?? [];
  const summarySites = analytics.BreachesSummary?.site
    ? analytics.BreachesSummary.site.split(";").filter(Boolean)
    : [];
  const allNames = Array.from(new Set([...breachNamesRaw, ...summarySites]));

  if (allNames.length === 0) {
    return { email: e, pwned: false, totalBreaches: 0, analytics: null, breaches: [] };
  }

  // Fetch detailed info per breach (parallel, capped)
  const details = await Promise.all(
    allNames.slice(0, 50).map(async (name) => {
      try {
        const r = await fetchJson<{ exposedBreaches?: BreachDetail[] }>(
          `${BASE}/breaches?breach=${encodeURIComponent(name)}`,
          signal,
        );
        return r.exposedBreaches?.[0] ?? null;
      } catch {
        return null;
      }
    }),
  );
  const breaches = details.filter((b): b is BreachDetail => !!b)
    .sort((a, b) => (b.breachedDate || "").localeCompare(a.breachedDate || ""));

  const m = analytics.BreachMetrics;
  const an: BreachAnalytics = {
    riskLabel: m?.risk?.[0]?.risk_label ?? "Unknown",
    riskScore: m?.risk?.[0]?.risk_score ?? 0,
    yearwise: m?.yearwise_details?.[0] ?? {},
    passwordStrength: m?.passwords_strength?.[0] ?? null,
    exposedDataCategories: (m?.xposed_data?.[0]?.children ?? []).map(cat => ({
      category: cat.name,
      items: (cat.children ?? []).map(it => ({
        name: it.name.replace(/^data_/, ""),
        value: it.value,
        group: it.group,
      })),
    })),
    breachNames: allNames,
  };

  return {
    email: e,
    pwned: true,
    totalBreaches: allNames.length,
    analytics: an,
    breaches,
  };
}
