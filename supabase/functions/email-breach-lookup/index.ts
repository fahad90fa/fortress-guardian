// Edge function: proxies XposedOrNot free breach API to bypass browser CORS.
// Privacy: only the email is forwarded to api.xposedornot.com over HTTPS.
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

const BASE = "https://api.xposedornot.com/v1";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface BreachDetail {
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

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { accept: "application/json", "user-agent": "lovable-breach-proxy/1.0" },
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`Upstream ${res.status} for ${url}`);
  }
  return res.json() as Promise<T>;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const url = new URL(req.url);
    const email = (url.searchParams.get("email") ?? "").trim().toLowerCase();

    if (!email || !EMAIL_RE.test(email) || email.length > 254) {
      return new Response(JSON.stringify({ error: "Invalid email" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const enc = encodeURIComponent(email);
    const [check, analytics] = await Promise.all([
      fetchJson<{ breaches?: string[][]; Error?: string }>(`${BASE}/check-email/${enc}`),
      fetchJson<any>(`${BASE}/breach-analytics?email=${enc}`),
    ]);

    const breachNamesRaw: string[] = check.breaches?.[0] ?? [];
    const summarySites: string[] = analytics?.BreachesSummary?.site
      ? String(analytics.BreachesSummary.site).split(";").filter(Boolean)
      : [];
    const allNames = Array.from(new Set([...breachNamesRaw, ...summarySites]));

    if (allNames.length === 0) {
      return new Response(
        JSON.stringify({ email, pwned: false, totalBreaches: 0, analytics: null, breaches: [] }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const details = await Promise.all(
      allNames.slice(0, 50).map(async (name) => {
        try {
          const r = await fetchJson<{ exposedBreaches?: BreachDetail[] }>(
            `${BASE}/breaches?breach=${encodeURIComponent(name)}`,
          );
          return r.exposedBreaches?.[0] ?? null;
        } catch {
          return null;
        }
      }),
    );
    const breaches = details
      .filter((b): b is BreachDetail => !!b)
      .sort((a, b) => (b.breachedDate || "").localeCompare(a.breachedDate || ""));

    const m = analytics?.BreachMetrics ?? {};
    const an = {
      riskLabel: m.risk?.[0]?.risk_label ?? "Unknown",
      riskScore: m.risk?.[0]?.risk_score ?? 0,
      yearwise: m.yearwise_details?.[0] ?? {},
      passwordStrength: m.passwords_strength?.[0] ?? null,
      exposedDataCategories: (m.xposed_data?.[0]?.children ?? []).map((cat: any) => ({
        category: cat.name,
        items: (cat.children ?? []).map((it: any) => ({
          name: String(it.name).replace(/^data_/, ""),
          value: it.value,
          group: it.group,
        })),
      })),
      breachNames: allNames,
    };

    return new Response(
      JSON.stringify({ email, pwned: true, totalBreaches: allNames.length, analytics: an, breaches }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown error";
    return new Response(JSON.stringify({ error: msg }), {
      status: 502,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
