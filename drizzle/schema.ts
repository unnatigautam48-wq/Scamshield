import { int, index, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

/**
 * An anonymized record of a scan. Raw user content is deliberately not stored.
 * `signals` is a compact JSON string so the public history can explain what was found.
 */
export const scans = mysqlTable(
  "scans",
  {
    id: int("id").autoincrement().primaryKey(),
    sessionId: varchar("sessionId", { length: 64 }).notNull(),
    inputMode: mysqlEnum("inputMode", ["message", "link", "screenshot", "document"]).notNull(),
    contentHash: varchar("contentHash", { length: 64 }).notNull(),
    riskScore: int("riskScore").notNull(),
    verdict: varchar("verdict", { length: 32 }).notNull(),
    source: varchar("source", { length: 32 }).notNull(),
    signals: text("signals").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  (table) => ({
    sessionCreatedIdx: index("scans_session_created_idx").on(table.sessionId, table.createdAt),
    createdIdx: index("scans_created_idx").on(table.createdAt),
  }),
);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type Scan = typeof scans.$inferSelect;
export type InsertScan = typeof scans.$inferInsert;
