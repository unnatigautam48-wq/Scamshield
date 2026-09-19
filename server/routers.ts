import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { EXAMPLES, INPUT_MODES, analyzeScan } from "../shared/scan";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { createScan, getRecentScans, hashScanContent } from "./db";
import { DocumentInputError, extractDocumentText } from "./document";

const scanInput = z.object({
  value: z.string().trim().min(1, "Paste a message or URL to scan").max(10_000, "Scan input is too long"),
  mode: z.enum(INPUT_MODES),
  sessionId: z.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session"),
});

const historyInput = z.object({
  sessionId: z.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session"),
});

const documentInput = z.object({
  fileName: z.string().trim().min(1).max(180),
  mimeType: z.string().trim().max(120),
  dataBase64: z.string().min(1).max(14_000_000),
  sessionId: z.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session"),
});

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  scan: router({
    analyze: publicProcedure.input(scanInput).mutation(async ({ input }) => {
      const result = analyzeScan(input.value, input.mode);

      await createScan({
        sessionId: input.sessionId,
        inputMode: input.mode,
        contentHash: hashScanContent(input.value),
        riskScore: result.risk,
        verdict: result.verdict,
        source: result.source,
        signals: JSON.stringify(result.signals.map(({ label, tone }) => ({ label, tone }))),
      });

      return result;
    }),

    analyzeDocument: publicProcedure.input(documentInput).mutation(async ({ input, ctx }) => {
      try {
        const bytes = Buffer.from(input.dataBase64, "base64");
        const text = await extractDocumentText(input.fileName, input.mimeType, bytes);
        const boundedText = text.slice(0, 10_000);
        const result = analyzeScan(boundedText, "document");

        await createScan({
          sessionId: input.sessionId,
          inputMode: "document",
          contentHash: hashScanContent(boundedText),
          riskScore: result.risk,
          verdict: result.verdict,
          source: result.source,
          signals: JSON.stringify(result.signals.map(({ label, tone }) => ({ label, tone }))),
        });

        return { ...result, fileName: input.fileName, truncated: text.length > boundedText.length };
      } catch (error) {
        if (error instanceof DocumentInputError) {
          throw new TRPCError({ code: "BAD_REQUEST", message: error.message });
        }
        console.error("[Scan] Document extraction failed", { fileName: input.fileName, error, requestId: ctx.req.headers["x-request-id"] });
        throw new TRPCError({ code: "BAD_REQUEST", message: "The document could not be read. Try a text-based PDF or DOCX." });
      }
    }),

    history: publicProcedure.input(historyInput).query(async ({ input }) => {
      const rows = await getRecentScans(input.sessionId);
      return rows.map((row) => ({
        id: row.id,
        mode: row.mode,
        label: row.mode === "link" ? EXAMPLES.link.label : row.mode === "document" ? "Document scan" : row.mode === "screenshot" ? "Screenshot scan" : "Message scan",
        risk: row.risk,
        verdict: row.verdict,
        createdAt: row.createdAt,
      }));
    }),
  }),
});

export type AppRouter = typeof appRouter;
