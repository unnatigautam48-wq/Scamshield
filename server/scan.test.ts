import { describe, expect, it } from "vitest";
import { EXAMPLES, analyzeScan, inspectUrl } from "../shared/scan";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import { DocumentInputError, extractDocumentText } from "./document";

describe("ScamShield scan engine", () => {
  it("flags urgency, credential requests, lookalike domains, and reply actions", () => {
    const result = analyzeScan(
      "URGENT: Verify your identity at https://secure-firstnational.co/verify today. Reply YES.",
      "message",
    );

    expect(result.verdict).toBe("High risk");
    expect(result.risk).toBeGreaterThanOrEqual(68);
    expect(result.signals.map((signal) => signal.label)).toEqual([
      "Artificial urgency",
      "Credential request",
      "Lookalike domain",
      "Reply-to-action",
    ]);
  });

  it("returns a calm but non-guaranteeing result for ordinary text", () => {
    const result = analyzeScan("Hey, are we still on for coffee at 5? See you soon.", "message");

    expect(result.verdict).toBe("Low risk");
    expect(result.risk).toBe(10);
    expect(result.signals[0]?.label).toBe("No obvious trigger found");
    expect(result.summary).toContain("not proof of safety");
    expect(result.riskBreakdown.pressure).toBe(12);
    expect(result.riskBreakdown.money).toBe(6);
  });

  it("explains destination risk without claiming a live reputation lookup", () => {
    const insight = inspectUrl("https://microsoft-support-login.com/account/verify");

    expect(insight?.hostname).toBe("microsoft-support-login.com");
    expect(insight?.isLookalike).toBe(true);
    expect(insight?.isSecure).toBe(true);
    expect(analyzeScan(insight?.url ?? "", "link").riskBreakdown.destination).toBe(92);
  });

  it("assigns different scores to different scam archetypes", () => {
    const bank = analyzeScan(EXAMPLES.bank.value, "message");
    const delivery = analyzeScan(EXAMPLES.delivery.value, "message");
    const ordinary = analyzeScan("Can you send me the notes from today?", "message");

    expect(new Set([bank.risk, delivery.risk, ordinary.risk]).size).toBe(3);
    expect(bank.risk).toBeGreaterThan(delivery.risk);
    expect(delivery.risk).toBeGreaterThan(ordinary.risk);
  });
});

describe("scan API validation", () => {
  it("rejects malformed anonymous sessions before database access", async () => {
    const ctx: TrpcContext = {
      user: null,
      req: {} as TrpcContext["req"],
      res: {} as TrpcContext["res"],
    };
    const caller = appRouter.createCaller(ctx);

    await expect(
      caller.scan.analyze({
        value: "test",
        mode: "message",
        sessionId: "bad",
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });
});

describe("document extraction", () => {
  it("extracts text files in memory", async () => {
    const text = await extractDocumentText("notice.txt", "text/plain", Buffer.from("URGENT: verify your account"));
    expect(text).toBe("URGENT: verify your account");
  });

  it("rejects unsupported file types clearly", async () => {
    await expect(extractDocumentText("photo.png", "image/png", Buffer.from("not-an-image"))).rejects.toBeInstanceOf(DocumentInputError);
  });
});
