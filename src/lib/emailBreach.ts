/**
 * Email breach lookup — calls our edge function proxy which fetches from
 * the free XposedOrNot API. The proxy is needed because XposedOrNot does
 * not return CORS headers for browser-origin requests.
 *
 * Important: NO legitimate API exposes actual leaked password values —
 * only the data classes/types that were exposed in each breach.
 */
import { supabase } from "@/integrations/supabase/client";

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

export async function checkEmailBreaches(email: string): Promise<EmailBreachReport> {
  const e = email.trim().toLowerCase();
  if (!isValidEmail(e)) throw new Error("Invalid email address");

  const { data, error } = await supabase.functions.invoke("email-breach-lookup", {
    body: null,
    method: "GET",
    // Pass email as query param via the URL — invoke supports this via headers/path workaround:
  });

  // supabase.functions.invoke doesn't expose query params directly; build URL manually.
  if (error || !data) {
    return await fetchViaUrl(e);
  }
  return data as EmailBreachReport;
}

async function fetchViaUrl(email: string): Promise<EmailBreachReport> {
  const url = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/email-breach-lookup?email=${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: {
      apikey: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
      Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Lookup failed (${res.status}) ${body.slice(0, 120)}`);
  }
  return res.json();
}
