import { Shield, Lock } from "lucide-react";
import { PasswordChecker } from "@/components/PasswordChecker";

const Index = () => {
  return (
    <main className="min-h-screen px-4 py-10 sm:py-16">
      <header className="max-w-3xl mx-auto text-center mb-10 sm:mb-14">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/30 bg-primary/10 text-xs font-medium text-primary mb-5 animate-pulse-glow">
          <Lock className="h-3 w-3" />
          Runs 100% in your browser
        </div>
        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight mb-3">
          <span className="text-gradient">Password Strength</span> Checker
        </h1>
        <p className="text-muted-foreground text-base sm:text-lg max-w-xl mx-auto">
          Real-time entropy analysis, breach detection via k-anonymity, and a secure generator.
          Your password never leaves this device.
        </p>
      </header>

      <PasswordChecker />

      <footer className="max-w-3xl mx-auto mt-12 text-center text-xs text-muted-foreground space-y-1">
        <p className="flex items-center justify-center gap-1.5">
          <Shield className="h-3 w-3" />
          Breach checks use the HaveIBeenPwned k-anonymity API — only the first 5 SHA-1 hash characters are sent.
        </p>
        <p>Crack times assume an offline attacker at 10¹⁰ guesses/sec on fast hashes.</p>
      </footer>
    </main>
  );
};

export default Index;
