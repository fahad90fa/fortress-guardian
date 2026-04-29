import { type PasswordAnalysis } from "@/lib/passwordAnalyzer";
import { Loader2, ShieldAlert } from "lucide-react";

interface Props {
  analysis: PasswordAnalysis;
  hibp: { pwned: boolean; count: number } | null;
  hibpLoading: boolean;
}

const TIER_COLOR_VAR = ["--strength-0", "--strength-1", "--strength-2", "--strength-3", "--strength-4"];

export function StrengthMeter({ analysis, hibp, hibpLoading }: Props) {
  const filled = analysis.length === 0 ? -1 : analysis.score;
  const colorVar = filled >= 0 ? TIER_COLOR_VAR[filled] : "--muted";

  return (
    <div className="space-y-2" id="strength-label" aria-live="polite">
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">Strength</span>
        <span
          className="font-semibold tabular-nums transition-colors"
          style={{ color: `hsl(var(${colorVar}))` }}
        >
          {analysis.length === 0 ? "—" : analysis.label}
          {hibp?.pwned && (
            <span className="ml-2 inline-flex items-center gap-1 text-xs font-medium text-destructive">
              <ShieldAlert className="h-3 w-3" /> breached {hibp.count.toLocaleString()}×
            </span>
          )}
          {hibpLoading && (
            <span className="ml-2 inline-flex items-center gap-1 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> checking breaches…
            </span>
          )}
        </span>
      </div>

      {/* 5-segment meter */}
      <div className="grid grid-cols-5 gap-1.5" role="progressbar" aria-valuemin={0} aria-valuemax={4} aria-valuenow={Math.max(0, filled)}>
        {[0, 1, 2, 3, 4].map(i => {
          const active = i <= filled;
          return (
            <div
              key={i}
              className="h-2 rounded-full transition-all duration-300 overflow-hidden bg-secondary/60"
            >
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: active ? "100%" : "0%",
                  background: active ? `hsl(var(${TIER_COLOR_VAR[filled]}))` : "transparent",
                  boxShadow: active && i === filled ? `0 0 12px hsl(var(${TIER_COLOR_VAR[filled]}) / 0.6)` : undefined,
                }}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
