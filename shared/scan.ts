export const INPUT_MODES = ["message", "link", "screenshot", "document"] as const;
export type InputMode = (typeof INPUT_MODES)[number];

export const FLAG_TONES = ["critical", "warning", "info"] as const;
export type FlagTone = (typeof FLAG_TONES)[number];

export type Signal = {
  label: string;
  detail: string;
  tone: FlagTone;
  evidence: string;
};

export type UrlInsight = {
  url: string;
  hostname: string;
  protocol: "HTTPS" | "HTTP" | "UNKNOWN";
  isSecure: boolean;
  isShortened: boolean;
  isLookalike: boolean;
  isDeepSubdomain: boolean;
  hasRiskyTld: boolean;
  operatorNote: string;
};

export type RiskBreakdown = {
  pressure: number;
  access: number;
  money: number;
  destination: number;
  behavior: number;
};

export type ScanAnalysis = {
  risk: number;
  verdict: "High risk" | "Needs review" | "Low risk";
  summary: string;
  signals: Signal[];
  nextSteps: string[];
  source: string;
  urlInsight: UrlInsight | null;
  riskBreakdown: RiskBreakdown;
};

export const EXAMPLES = {
  bank: {
    label: "Bank alert",
    mode: "message" as const,
    value:
      "URGENT: Your account will be suspended today. Verify your identity immediately at https://secure-firstnational.co/verify to avoid losing access. Reply YES to confirm.",
  },
  delivery: {
    label: "Delivery text",
    mode: "message" as const,
    value:
      "Your parcel could not be delivered. Pay the $2.99 redelivery fee within 12 hours: https://bit.ly/4parcel-fee",
  },
  link: {
    label: "Suspicious link",
    mode: "link" as const,
    value: "https://microsoft-support-login.com/account/verify?session=8841",
  },
} as const;

const URL_PATTERN = /https?:\/\/[^\s<>'"]+/i;
const SHORTENER_PATTERN = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|shorturl\.at|is\.gd)$/i;
const RISKY_TLD_PATTERN = /\.(zip|top|click|support|live|work|tk|gq|ml|cf|ru)$/i;

export function inspectUrl(value: string): UrlInsight | null {
  const rawUrl = value.match(URL_PATTERN)?.[0]?.replace(/[),.!?]+$/, "");
  if (!rawUrl) return null;

  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const isShortened = SHORTENER_PATTERN.test(hostname);
    const isLookalike = /(microsoft-support|secure-firstnational|paypa1|appleid-security|amazon-account|netflix-billing)/i.test(hostname);
    const isDeepSubdomain = hostname.split(".").length >= 4;
    const hasRiskyTld = RISKY_TLD_PATTERN.test(hostname);
    const isSecure = parsed.protocol === "https:";
    const operatorNote = isLookalike
      ? "Brand-like hostname; verify through the official app instead."
      : isShortened
        ? "Short link hides the final destination."
        : hasRiskyTld
          ? "Unusual top-level domain deserves independent verification."
          : isSecure
            ? "Encrypted transport does not prove the site is legitimate."
            : "No HTTPS protection detected.";

    return {
      url: rawUrl,
      hostname,
      protocol: isSecure ? "HTTPS" : parsed.protocol === "http:" ? "HTTP" : "UNKNOWN",
      isSecure,
      isShortened,
      isLookalike,
      isDeepSubdomain,
      hasRiskyTld,
      operatorNote,
    };
  } catch {
    return null;
  }
}

export function analyzeScan(value: string, mode: InputMode): ScanAnalysis {
  const text = value.trim();
  const signals: Signal[] = [];
  const urlInsight = inspectUrl(text);

  const urgency = /(urgent|immediately|act now|within \d+ hours?|today|expires?|suspended|last warning|final notice)/i;
  const credentialRequest = /(verify (your )?(identity|account|details)|confirm (your )?(account|password|details)|login|sign in|one[- ]time|otp|password|security code)/i;
  const paymentRequest = /(?:\bpay\b|\bpayment\b|\bfee\b|\brefund\b|\bprize\b|\bgift card\b|\btransfer\b|\binvoice\b|\$\d|\bmoney\b)/i;
  const shortened = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|shorturl\.at)/i;
  const lookalike = /(microsoft-support|secure-firstnational|paypa1|appleid-security|amazon-account|netflix-billing)/i;
  const replyRequest = /(reply|text|call|click)\s+[A-Z0-9]+/i;

  if (urgency.test(text)) {
    signals.push({ label: "Artificial urgency", detail: "The message pressures you to act before you have time to verify it.", tone: "critical", evidence: text.match(urgency)?.[0] ?? "urgent language" });
  }
  if (credentialRequest.test(text)) {
    signals.push({ label: "Credential request", detail: "It asks for access, identity, or security details through the message.", tone: "critical", evidence: text.match(credentialRequest)?.[0] ?? "account verification" });
  }
  if (paymentRequest.test(text)) {
    signals.push({ label: "Money is involved", detail: "A payment, fee, reward, or transfer makes this a high-value target for fraud.", tone: "warning", evidence: text.match(paymentRequest)?.[0] ?? "payment language" });
  }
  if (shortened.test(text)) {
    signals.push({ label: "Obscured destination", detail: "A shortened link hides the website you would actually visit.", tone: "critical", evidence: text.match(shortened)?.[0] ?? "shortened URL" });
  }
  if (lookalike.test(text)) {
    signals.push({ label: "Lookalike domain", detail: "The destination borrows a trusted brand name but is not the official domain.", tone: "critical", evidence: text.match(lookalike)?.[0] ?? "brand-like domain" });
  }
  if (replyRequest.test(text)) {
    signals.push({ label: "Reply-to-action", detail: "It asks you to respond from the same unverified conversation.", tone: "warning", evidence: text.match(replyRequest)?.[0] ?? "reply instruction" });
  }
  if (mode === "link" && !/^https:\/\//i.test(text)) {
    signals.push({ label: "Unencrypted link", detail: "This URL does not begin with HTTPS, so the connection may not be protected.", tone: "warning", evidence: "http://" });
  }
  if (urlInsight?.isDeepSubdomain) {
    signals.push({ label: "Deeply nested domain", detail: "Multiple subdomains can make the real owner of a destination harder to spot.", tone: "warning", evidence: urlInsight.hostname });
  }
  if (urlInsight?.hasRiskyTld) {
    signals.push({ label: "Risky top-level domain", detail: "This top-level domain is frequently used in throwaway or impersonation campaigns.", tone: "warning", evidence: urlInsight.hostname.split(".").slice(-1)[0] ?? "unusual TLD" });
  }
  if (signals.length === 0) {
    signals.push({ label: "No obvious trigger found", detail: "The quick scan did not find common scam patterns. That is not proof of safety.", tone: "info", evidence: "pattern scan" });
  }

  const signalWeights: Record<string, number> = {
    "Artificial urgency": 18,
    "Credential request": 22,
    "Money is involved": 14,
    "Obscured destination": 18,
    "Lookalike domain": 24,
    "Reply-to-action": 10,
    "Unencrypted link": 8,
    "Deeply nested domain": 7,
    "Risky top-level domain": 10,
    "No obvious trigger found": 0,
  };
  const weightedRisk = 10 + signals.reduce((total, signal) => total + (signalWeights[signal.label] ?? 5), 0);
  const risk = Math.min(99, Math.max(8, weightedRisk));
  const verdict = risk >= 68 ? "High risk" : risk >= 40 ? "Needs review" : "Low risk";
  const summary = verdict === "High risk"
    ? "This message combines multiple patterns commonly used to rush people into unsafe clicks, replies, or payments."
    : verdict === "Needs review"
      ? "There are a few signals worth checking before you interact. Use an official channel to verify the request."
      : "Nothing in this quick scan looks immediately suspicious, but that is not proof of safety—stay cautious with unexpected messages.";
  const nextSteps = verdict === "High risk"
    ? ["Do not click, reply, or share any code from this message.", "Open the organization’s official app or type its website yourself.", "Block and report the sender after saving the message as evidence."]
    : verdict === "Needs review"
      ? ["Pause before clicking or sending information.", "Verify the request using a phone number or website you already trust.", "If the request is unexpected, treat it as suspicious and report it."]
      : ["Check the sender address and destination before continuing.", "Never share passwords or one-time codes in response to a message.", "When in doubt, verify through a separate trusted channel."];

  return {
    risk,
    verdict,
    summary,
    signals: signals.slice(0, 6),
    nextSteps,
    source: mode === "link" ? "URL quick scan" : mode === "screenshot" ? "Screenshot notes" : mode === "document" ? "Document scan" : "Message quick scan",
    urlInsight,
    riskBreakdown: {
      pressure: Math.min(100, urgency.test(text) ? 85 : 12),
      access: Math.min(100, credentialRequest.test(text) ? 90 : 8),
      money: Math.min(100, paymentRequest.test(text) ? 78 : 6),
      destination: Math.min(100, urlInsight ? (urlInsight.isLookalike || urlInsight.isShortened ? 92 : urlInsight.isSecure ? 30 : 72) : 5),
      behavior: Math.min(100, replyRequest.test(text) ? 74 : 10),
    },
  };
}
