import { useState } from "react";
import { Mail, Loader2, ShieldAlert, ShieldCheck, ExternalLink, Calendar, Database, AlertTriangle, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import { checkEmailBreaches, isValidEmail, type EmailBreachReport } from "@/lib/emailBreach";

const RISK_COLOR: Record<string, string> = {
  Critical: "--strength-0",
  High: "--strength-1",
  Medium: "--strength-2",
  Low: "--strength-3",
  Unknown: "--muted-foreground",
};

export function EmailBreachLookup() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<EmailBreachReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleCheck = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setError(null);
    setReport(null);
    if (!isValidEmail(email)) {
      setError("Please enter a valid email address.");
      return;
    }
    try {
      setLoading(true);
      const result = await checkEmailBreaches(email);
      setReport(result);
      if (!result.pwned) toast.success("Good news — no breaches found for this email.");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Lookup failed";
      setError(msg);
      toast.error("Lookup failed", { description: msg });
    } finally {
      setLoading(false);
    }
  };

  const riskColorVar = report?.analytics ? (RISK_COLOR[report.analytics.riskLabel] ?? "--muted-foreground") : "--muted-foreground";

  return (
    <section className="glass rounded-2xl p-6 sm:p-8 border border-border/50">
      <div className="mb-5">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Mail className="h-5 w-5 text-primary" aria-hidden="true" />
          Email breach lookup
        </h2>
        <p className="text-sm text-muted-foreground mt-0.5">
          Check if your email appeared in known data breaches. Powered by{" "}
          <a href="https://xposedornot.com" target="_blank" rel="noopener noreferrer" className="underline hover:text-primary">
            XposedOrNot
          </a>{" "}
          (free, no key).
        </p>
      </div>

      <form onSubmit={handleCheck} className="flex flex-col sm:flex-row gap-2">
        <div className="flex-1">
          <Label htmlFor="email" className="sr-only">Email address</Label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoComplete="email"
            spellCheck={false}
            className="h-11 bg-input/60"
            aria-invalid={!!error}
            aria-describedby={error ? "email-error" : undefined}
          />
        </div>
        <Button type="submit" disabled={loading || !email} className="h-11 gap-2 sm:w-36">
          {loading ? <><Loader2 className="h-4 w-4 animate-spin" /> Checking…</> : <>Check breaches</>}
        </Button>
      </form>

      {error && <p id="email-error" className="text-sm text-destructive mt-2">{error}</p>}

      {/* Privacy note */}
      <div className="mt-3 flex items-start gap-2 text-xs text-muted-foreground rounded-lg bg-secondary/30 border border-border/40 p-3">
        <Info className="h-3.5 w-3.5 shrink-0 mt-0.5 text-primary" />
        <span>
          <strong className="text-foreground">No legitimate service exposes actual leaked passwords.</strong>{" "}
          You'll see which breaches your email appeared in and what types of data were exposed (passwords, names, addresses, etc.) — never the password values themselves.
        </span>
      </div>

      {/* Results */}
      {report && (
        <div className="mt-6 space-y-5 animate-fade-up">
          {/* Verdict */}
          <div
            className="rounded-xl p-5 border flex items-center gap-4"
            style={{
              borderColor: `hsl(var(${report.pwned ? riskColorVar : "--accent"}) / 0.4)`,
              background: `hsl(var(${report.pwned ? riskColorVar : "--accent"}) / 0.08)`,
            }}
          >
            {report.pwned ? (
              <ShieldAlert className="h-8 w-8 shrink-0" style={{ color: `hsl(var(${riskColorVar}))` }} />
            ) : (
              <ShieldCheck className="h-8 w-8 shrink-0 text-accent" />
            )}
            <div className="flex-1 min-w-0">
              <div className="font-semibold text-base">
                {report.pwned
                  ? `Found in ${report.totalBreaches} known ${report.totalBreaches === 1 ? "breach" : "breaches"}`
                  : "No breaches found"}
              </div>
              <div className="text-sm text-muted-foreground truncate">{report.email}</div>
            </div>
            {report.analytics && (
              <div className="text-right shrink-0">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Risk</div>
                <div className="font-mono font-semibold text-lg" style={{ color: `hsl(var(${riskColorVar}))` }}>
                  {report.analytics.riskScore}
                  <span className="text-xs ml-1 text-muted-foreground">/100</span>
                </div>
                <div className="text-xs" style={{ color: `hsl(var(${riskColorVar}))` }}>
                  {report.analytics.riskLabel}
                </div>
              </div>
            )}
          </div>

          {/* Exposed data types */}
          {report.analytics && report.analytics.exposedDataCategories.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Database className="h-3.5 w-3.5" /> What data was exposed
              </h3>
              <div className="space-y-3">
                {report.analytics.exposedDataCategories.map((cat) => (
                  <div key={cat.category}>
                    <div className="text-xs font-medium text-muted-foreground mb-1.5">{cat.category}</div>
                    <div className="flex flex-wrap gap-1.5">
                      {cat.items.map((item) => (
                        <Tooltip key={item.name}>
                          <TooltipTrigger asChild>
                            <span className="inline-flex items-center gap-1.5 rounded-md bg-secondary/60 border border-border/50 px-2 py-1 text-xs cursor-help">
                              {item.name}
                              <span className="font-mono text-muted-foreground">×{item.value}</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>Exposed in {item.value} breach{item.value === 1 ? "" : "es"}</TooltipContent>
                        </Tooltip>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Password risk summary */}
          {report.analytics?.passwordStrength && (
            <div className="rounded-lg bg-secondary/30 border border-border/40 p-4">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="h-4 w-4 text-strength-1" style={{ color: "hsl(var(--strength-1))" }} />
                <h3 className="text-sm font-semibold">Password storage in those breaches</h3>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                <PwStat label="Plain text" value={report.analytics.passwordStrength.PlainText} colorVar="--strength-0" />
                <PwStat label="Easy to crack" value={report.analytics.passwordStrength.EasyToCrack} colorVar="--strength-1" />
                <PwStat label="Strong hash" value={report.analytics.passwordStrength.StrongHash} colorVar="--strength-3" />
                <PwStat label="Unknown" value={report.analytics.passwordStrength.Unknown} colorVar="--muted-foreground" />
              </div>
              <p className="text-xs text-muted-foreground mt-3">
                If "plain text" or "easy to crack" is non-zero, change your password on those sites and anywhere else you reused it.
              </p>
            </div>
          )}

          {/* Breach list */}
          {report.breaches.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
                Breaches ({report.breaches.length})
              </h3>
              <ul className="space-y-3">
                {report.breaches.map((b) => (
                  <li key={b.breachID} className="rounded-xl border border-border/50 bg-secondary/30 p-4">
                    <div className="flex items-start gap-3">
                      {b.logo && (
                        <img
                          src={b.logo}
                          alt=""
                          loading="lazy"
                          className="h-10 w-10 rounded-md object-contain bg-background/60 p-1 shrink-0"
                          onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
                        />
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                          <h4 className="font-semibold">{b.breachID}</h4>
                          {b.domain && <span className="text-xs text-muted-foreground">{b.domain}</span>}
                          {b.verified && (
                            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/15 text-accent">verified</span>
                          )}
                          {b.sensitive && (
                            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-destructive/15 text-destructive">sensitive</span>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground mt-1">
                          <span className="inline-flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {b.breachedDate ? new Date(b.breachedDate).toLocaleDateString(undefined, { year: "numeric", month: "short" }) : "Unknown"}
                          </span>
                          {b.exposedRecords > 0 && (
                            <span className="font-mono">{b.exposedRecords.toLocaleString()} records</span>
                          )}
                          {b.industry && <span>{b.industry}</span>}
                        </div>
                        {b.exposedData?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {b.exposedData.map((d) => (
                              <span
                                key={d}
                                className="text-[11px] px-1.5 py-0.5 rounded border"
                                style={
                                  /password/i.test(d)
                                    ? { borderColor: "hsl(var(--destructive) / 0.4)", color: "hsl(var(--destructive))", background: "hsl(var(--destructive) / 0.08)" }
                                    : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }
                                }
                              >
                                {d}
                              </span>
                            ))}
                          </div>
                        )}
                        {b.exposureDescription && (
                          <p className="text-xs text-muted-foreground mt-2 line-clamp-3">{b.exposureDescription}</p>
                        )}
                        {b.referenceURL && (
                          <a
                            href={b.referenceURL}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-primary hover:underline mt-2"
                          >
                            More details <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function PwStat({ label, value, colorVar }: { label: string; value: number; colorVar: string }) {
  return (
    <div className="rounded-md bg-background/40 border border-border/40 p-2">
      <div className="font-mono font-semibold text-base" style={{ color: `hsl(var(${colorVar}))` }}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mt-0.5">{label}</div>
    </div>
  );
}
