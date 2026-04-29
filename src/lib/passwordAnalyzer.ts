/**
 * Password analyzer — pure functions, runs entirely in-browser.
 * Computes Shannon entropy, detects patterns, dictionary hits, sequences,
 * and produces an overall score 0..4 plus actionable suggestions.
 */
import { isCommonPassword } from "./commonPasswords";

export type StrengthLevel = 0 | 1 | 2 | 3 | 4;

export const STRENGTH_LABELS: Record<StrengthLevel, string> = {
  0: "Very Weak",
  1: "Weak",
  2: "Medium",
  3: "Strong",
  4: "Very Strong",
};

export interface AnalysisIssue {
  severity: "high" | "medium" | "low";
  message: string;
}

export interface AnalysisSuggestion {
  message: string;
}

export interface PasswordAnalysis {
  password: string;
  length: number;
  hasLower: boolean;
  hasUpper: boolean;
  hasDigit: boolean;
  hasSymbol: boolean;
  charsetSize: number;
  entropyBits: number;     // entropy assuming attacker knows charset (length * log2(charset))
  shannonEntropy: number;  // empirical Shannon entropy of the string
  score: StrengthLevel;
  label: string;
  issues: AnalysisIssue[];
  suggestions: AnalysisSuggestion[];
  isCommon: boolean;
  hasSequence: boolean;
  hasRepeats: boolean;
  hasKeyboardPattern: boolean;
  crackTimeSeconds: number;
  crackTimeHuman: string;
}

const KEYBOARD_ROWS = [
  "`1234567890-=",
  "qwertyuiop[]\\",
  "asdfghjkl;'",
  "zxcvbnm,./",
];

function charsetSizeFor(pw: string): number {
  let size = 0;
  if (/[a-z]/.test(pw)) size += 26;
  if (/[A-Z]/.test(pw)) size += 26;
  if (/\d/.test(pw)) size += 10;
  if (/[^A-Za-z0-9]/.test(pw)) size += 33;
  return size || 1;
}

/** Empirical Shannon entropy H = -Σ p_i log2 p_i (bits per character). */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function hasRepeatedChars(pw: string): boolean {
  return /(.)\1{2,}/.test(pw);
}

/** Detects ascending or descending sequences of length >=4 (alphabetic or numeric). */
function hasSequence(pw: string): boolean {
  if (pw.length < 4) return false;
  const lower = pw.toLowerCase();
  for (let i = 0; i <= lower.length - 4; i++) {
    let asc = true, desc = true;
    for (let j = 1; j < 4; j++) {
      const diff = lower.charCodeAt(i + j) - lower.charCodeAt(i + j - 1);
      if (diff !== 1) asc = false;
      if (diff !== -1) desc = false;
    }
    if (asc || desc) return true;
  }
  return false;
}

/** Detects substrings of length >=4 that come from a single keyboard row. */
function hasKeyboardPattern(pw: string): boolean {
  if (pw.length < 4) return false;
  const lower = pw.toLowerCase();
  for (let i = 0; i <= lower.length - 4; i++) {
    const slice = lower.slice(i, i + 4);
    for (const row of KEYBOARD_ROWS) {
      if (row.includes(slice) || row.split("").reverse().join("").includes(slice)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Estimate crack time assuming an offline attacker at 1e10 hashes/sec
 * (rough GPU-on-fast-hash assumption — conservative for awareness).
 */
function estimateCrackTime(entropyBits: number): { seconds: number; human: string } {
  const guessesPerSec = 1e10;
  const guesses = Math.pow(2, entropyBits) / 2; // average half search space
  const seconds = guesses / guessesPerSec;
  return { seconds, human: humanizeDuration(seconds) };
}

export function humanizeDuration(seconds: number): string {
  if (!isFinite(seconds) || seconds > 1e15) return "centuries";
  if (seconds < 1e-3) return "instant";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  const units: Array<[number, string]> = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [365, "day"],
    [100, "year"],
    [10, "century"],
  ];
  let value = seconds;
  let unit = "second";
  for (const [factor, name] of units) {
    if (value < factor) { unit = name; break; }
    value /= factor;
    unit = name;
  }
  const rounded = value < 10 ? value.toFixed(1) : Math.round(value).toString();
  const plural = parseFloat(rounded) === 1 ? "" : "s";
  return `${rounded} ${unit}${plural}`;
}

export function analyzePassword(password: string): PasswordAnalysis {
  const length = password.length;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  const charsetSize = charsetSizeFor(password);
  const entropyBits = length * Math.log2(charsetSize);
  const sEntropy = shannonEntropy(password);

  const isCommon = isCommonPassword(password);
  const sequence = hasSequence(password);
  const repeats = hasRepeatedChars(password);
  const keyboard = hasKeyboardPattern(password);

  const issues: AnalysisIssue[] = [];
  const suggestions: AnalysisSuggestion[] = [];

  if (length === 0) {
    // empty handled by caller
  } else {
    if (length < 8) issues.push({ severity: "high", message: "Too short — use at least 12 characters." });
    else if (length < 12) issues.push({ severity: "medium", message: "Consider 12+ characters for stronger security." });
    if (!hasUpper) suggestions.push({ message: "Add uppercase letters (A–Z)." });
    if (!hasLower) suggestions.push({ message: "Add lowercase letters (a–z)." });
    if (!hasDigit) suggestions.push({ message: "Add numbers (0–9)." });
    if (!hasSymbol) suggestions.push({ message: "Add symbols (!@#$…)." });
    if (isCommon) issues.push({ severity: "high", message: "This password appears in common breach lists." });
    if (sequence) issues.push({ severity: "medium", message: "Avoid sequences like 1234 or abcd." });
    if (repeats) issues.push({ severity: "medium", message: "Avoid 3+ repeated characters in a row." });
    if (keyboard) issues.push({ severity: "medium", message: "Avoid keyboard patterns like qwerty or asdf." });
  }

  // Scoring: start from entropy, penalize for issues.
  let effectiveBits = entropyBits;
  if (isCommon) effectiveBits = Math.min(effectiveBits, 8);
  if (sequence) effectiveBits -= 10;
  if (repeats) effectiveBits -= 8;
  if (keyboard) effectiveBits -= 10;
  effectiveBits = Math.max(0, effectiveBits);

  let score: StrengthLevel = 0;
  if (effectiveBits >= 80) score = 4;
  else if (effectiveBits >= 60) score = 3;
  else if (effectiveBits >= 40) score = 2;
  else if (effectiveBits >= 25) score = 1;

  const { seconds, human } = estimateCrackTime(effectiveBits);

  return {
    password,
    length,
    hasLower, hasUpper, hasDigit, hasSymbol,
    charsetSize,
    entropyBits,
    shannonEntropy: sEntropy,
    score,
    label: STRENGTH_LABELS[score],
    issues,
    suggestions,
    isCommon,
    hasSequence: sequence,
    hasRepeats: repeats,
    hasKeyboardPattern: keyboard,
    crackTimeSeconds: seconds,
    crackTimeHuman: human,
  };
}

/** Generate a cryptographically secure password. */
export function generatePassword(length = 20, opts?: {
  upper?: boolean; lower?: boolean; digits?: boolean; symbols?: boolean;
}): string {
  const o = { upper: true, lower: true, digits: true, symbols: true, ...opts };
  let charset = "";
  if (o.lower) charset += "abcdefghijkmnopqrstuvwxyz";
  if (o.upper) charset += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (o.digits) charset += "23456789";
  if (o.symbols) charset += "!@#$%^&*()-_=+[]{};:,.?/";
  if (!charset) return "";
  const out: string[] = [];
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  for (let i = 0; i < length; i++) out.push(charset[arr[i] % charset.length]);
  return out.join("");
}
