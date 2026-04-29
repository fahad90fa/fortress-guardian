import { type PasswordAnalysis } from "@/lib/passwordAnalyzer";
import { AlertTriangle, Lightbulb, CheckCircle2, ShieldAlert } from "lucide-react";
import { useMemo } from "react";

interface Props {
  analysis: PasswordAnalysis;
  hibp: { pwned: boolean; count: number } | null;
  hibpLoading: boolean;
}

export function AnalysisDetails({ analysis, hibp }: Props) {
  const checks = useMemo(() => ([
    { label: "12+ characters", ok: analysis.length >= 12 },
    { label: "Lowercase letters", ok: analysis.hasLower },
    { label: "Uppercase letters", ok: analysis.hasUpper },
    { label: "Numbers", ok: analysis.hasDigit },
    { label: "Symbols", ok: analysis.hasSymbol },
    { label: "No repeats / sequences", ok: !analysis.hasRepeats && !analysis.hasSequence && !analysis.hasKeyboardPattern },
    { label: "Not a common password", ok: !analysis.isCommon && !hibp?.pwned },
  ]), [analysis, hibp]);

  if (analysis.length === 0) return null;

  return (
    <section className="glass rounded-2xl p-6 sm:p-8 border border-border/50 animate-fade-up">
      <div className="grid sm:grid-cols-2 gap-6">
        {/* Checks */}
        <div>
          <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">Checks</h3>
          <ul className="space-y-2">
            {checks.map(c => (
              <li key={c.label} className="flex items-center gap-2 text-sm">
                {c.ok ? (
                  <CheckCircle2 className="h-4 w-4 text-accent shrink-0" aria-hidden="true" />
                ) : (
                  <span className="h-4 w-4 rounded-full border-2 border-muted-foreground/40 shrink-0" aria-hidden="true" />
                )}
                <span className={c.ok ? "text-foreground" : "text-muted-foreground"}>{c.label}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Issues + suggestions */}
        <div className="space-y-4">
          {analysis.issues.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5" /> Issues
              </h3>
              <ul className="space-y-1.5">
                {analysis.issues.map((it, i) => (
                  <li key={i} className="text-sm flex gap-2">
                    <span
                      className="mt-1.5 h-1.5 w-1.5 rounded-full shrink-0"
                      style={{
                        background: it.severity === "high" ? "hsl(var(--destructive))" :
                                    it.severity === "medium" ? "hsl(var(--strength-1))" :
                                    "hsl(var(--strength-2))",
                      }}
                    />
                    <span>{it.message}</span>
                  </li>
                ))}
                {hibp?.pwned && (
                  <li className="text-sm flex gap-2 text-destructive">
                    <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" />
                    <span>Found in {hibp.count.toLocaleString()} known breaches — never use this.</span>
                  </li>
                )}
              </ul>
            </div>
          )}

          {analysis.suggestions.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Lightbulb className="h-3.5 w-3.5" /> Suggestions
              </h3>
              <ul className="space-y-1.5">
                {analysis.suggestions.map((s, i) => (
                  <li key={i} className="text-sm text-muted-foreground">→ {s.message}</li>
                ))}
              </ul>
            </div>
          )}

          {analysis.issues.length === 0 && analysis.suggestions.length === 0 && (
            <div className="rounded-lg bg-accent/10 border border-accent/30 p-4 text-sm">
              <CheckCircle2 className="h-5 w-5 text-accent inline mr-2" />
              Excellent password — meets all key criteria.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
