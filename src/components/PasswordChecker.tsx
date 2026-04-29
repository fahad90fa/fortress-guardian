import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, Copy, RefreshCw, Check, ShieldAlert, ShieldCheck, Sparkles, Clock, Cpu, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { analyzePassword, generatePassword, type PasswordAnalysis } from "@/lib/passwordAnalyzer";
import { checkHibp } from "@/lib/hibp";
import { StrengthMeter } from "./StrengthMeter";
import { AnalysisDetails } from "./AnalysisDetails";

export function PasswordChecker() {
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [analysis, setAnalysis] = useState<PasswordAnalysis>(() => analyzePassword(""));
  const [hibp, setHibp] = useState<{ pwned: boolean; count: number } | null>(null);
  const [hibpLoading, setHibpLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Generator options
  const [genLen, setGenLen] = useState(20);
  const [genUpper, setGenUpper] = useState(true);
  const [genLower, setGenLower] = useState(true);
  const [genDigits, setGenDigits] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);

  // Analyze locally on every change (instant, never logged)
  useEffect(() => {
    setAnalysis(analyzePassword(password));
    setHibp(null);
  }, [password]);

  // Debounced HIBP check via k-anonymity (privacy-preserving)
  useEffect(() => {
    if (!password) return;
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const t = setTimeout(async () => {
      try {
        setHibpLoading(true);
        const result = await checkHibp(password, ctrl.signal);
        if (!ctrl.signal.aborted) setHibp(result);
      } catch (err) {
        if (!ctrl.signal.aborted) {
          // network failure — silent, local analysis still works
        }
      } finally {
        if (!ctrl.signal.aborted) setHibpLoading(false);
      }
    }, 600);
    return () => { clearTimeout(t); ctrl.abort(); };
  }, [password]);

  const handleGenerate = () => {
    const pw = generatePassword(genLen, {
      upper: genUpper, lower: genLower, digits: genDigits, symbols: genSymbols,
    });
    if (!pw) {
      toast.error("Select at least one character set.");
      return;
    }
    setPassword(pw);
    setReveal(true);
  };

  const handleCopy = async () => {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      toast.success("Copied to clipboard", { description: "Clear your clipboard after pasting." });
    } catch {
      toast.error("Could not access clipboard");
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-6">
      {/* Input card */}
      <section className="glass rounded-2xl p-6 sm:p-8 border border-border/50 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none bg-gradient-hero" aria-hidden="true" />
        <div className="relative space-y-5">
          <div className="space-y-2">
            <Label htmlFor="password" className="flex items-center gap-2 text-sm font-medium">
              <KeyRound className="h-4 w-4 text-primary" aria-hidden="true" />
              Test your password
            </Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  id="password"
                  type={reveal ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Type or paste a password…"
                  autoComplete="off"
                  autoCorrect="off"
                  spellCheck={false}
                  aria-describedby="strength-label"
                  className="pr-20 h-12 font-mono text-base bg-input/60 border-border/60 focus-visible:ring-primary"
                />
                <div className="absolute right-1 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button" variant="ghost" size="icon"
                        onClick={() => setReveal(v => !v)}
                        aria-label={reveal ? "Hide password" : "Show password"}
                        className="h-9 w-9"
                      >
                        {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>{reveal ? "Hide" : "Show"}</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        type="button" variant="ghost" size="icon"
                        onClick={handleCopy} disabled={!password}
                        aria-label="Copy password"
                        className="h-9 w-9"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Copy</TooltipContent>
                  </Tooltip>
                </div>
              </div>
            </div>
          </div>

          <StrengthMeter analysis={analysis} hibp={hibp} hibpLoading={hibpLoading} />

          {/* Quick stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2">
            <Stat icon={<Sparkles className="h-3.5 w-3.5" />} label="Entropy" value={`${analysis.entropyBits.toFixed(1)} bits`} tip="Length × log₂(charset). Higher = harder to brute-force." />
            <Stat icon={<Cpu className="h-3.5 w-3.5" />} label="Shannon" value={`${analysis.shannonEntropy.toFixed(2)} b/c`} tip="Empirical entropy per character of this string." />
            <Stat icon={<Clock className="h-3.5 w-3.5" />} label="Crack time" value={analysis.crackTimeHuman} tip="Estimated offline crack at 10¹⁰ guesses/sec." />
            <Stat icon={analysis.score >= 3 ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />} label="Charset" value={`${analysis.charsetSize} chars`} tip="Effective alphabet size based on character classes used." />
          </div>
        </div>
      </section>

      {/* Analysis details */}
      <AnalysisDetails analysis={analysis} hibp={hibp} hibpLoading={hibpLoading} />

      {/* Generator */}
      <section className="glass rounded-2xl p-6 sm:p-8 border border-border/50">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-accent" aria-hidden="true" />
              Secure generator
            </h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              Cryptographically random — uses <code className="text-xs">crypto.getRandomValues</code>.
            </p>
          </div>
          <Button onClick={handleGenerate} className="gap-2" size="sm">
            <RefreshCw className="h-4 w-4" /> Generate
          </Button>
        </div>

        <div className="space-y-5">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label htmlFor="length">Length</Label>
              <span className="font-mono text-sm text-primary">{genLen}</span>
            </div>
            <Slider id="length" min={8} max={64} step={1} value={[genLen]} onValueChange={([v]) => setGenLen(v)} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <ToggleRow id="upper" label="A-Z" checked={genUpper} onChange={setGenUpper} />
            <ToggleRow id="lower" label="a-z" checked={genLower} onChange={setGenLower} />
            <ToggleRow id="digits" label="0-9" checked={genDigits} onChange={setGenDigits} />
            <ToggleRow id="symbols" label="!@#$" checked={genSymbols} onChange={setGenSymbols} />
          </div>
        </div>
      </section>
    </div>
  );
}

function Stat({ icon, label, value, tip }: { icon: React.ReactNode; label: string; value: string; tip: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className="rounded-lg bg-secondary/40 border border-border/40 px-3 py-2 cursor-help">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
            {icon}{label}
          </div>
          <div className="font-mono text-sm mt-0.5 truncate">{value}</div>
        </div>
      </TooltipTrigger>
      <TooltipContent>{tip}</TooltipContent>
    </Tooltip>
  );
}

function ToggleRow({ id, label, checked, onChange }: { id: string; label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-secondary/40 border border-border/40 px-3 py-2">
      <Label htmlFor={id} className="font-mono text-sm cursor-pointer">{label}</Label>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

// Re-export for tree-shaking visibility
export { Check };
