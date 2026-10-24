import { Buffer } from 'node:buffer';
import { z } from 'zod';

/** Minimum similarity required for a verified image match. */
export const VERIFIED_MIN_SIMILARITY = 0.90;

/** Minimum similarity required for a possible image match. */
export const POSSIBLE_MIN_SIMILARITY = 0.75;

/** Safety decision that gates image analysis and subsequent investigation. */
export const SafetyGateSchema = z.object({
  possibleMinor: z.boolean(),
  blocked: z.boolean(),
  reason: z.string().optional(),
});
export type SafetyGate = z.infer<typeof SafetyGateSchema>;

/** Privacy-preserving image analysis metadata and up to five search queries. */
export const ImageAnalysisResultSchema = z.object({
  imageHash: z.string().regex(/^[a-fA-F0-9]{64}$/),
  searchQueries: z.array(z.string()).max(5),
  safety: SafetyGateSchema,
  model: z.string(),
  generatedAt: z.iso.datetime({ offset: true }),
  isMock: z.boolean(),
});
export type ImageAnalysisResult = z.infer<typeof ImageAnalysisResultSchema>;

/** In-memory image input; image bytes must never be persisted or logged. */
export const VisionQueryRequestSchema = z.object({
  imageBuffer: z.custom<Buffer>(
    (value: unknown): value is Buffer => Buffer.isBuffer(value),
    { message: 'Expected an in-memory Buffer' },
  ),
  mimeType: z.enum(['image/jpeg', 'image/png', 'image/webp']),
  userContext: z.string().max(300).optional(),
});
export type VisionQueryRequest = z.infer<typeof VisionQueryRequestSchema>;

/** A discovered page or image with an explicit verification status and source. */
export const CandidateMatchSchema = z.object({
  url: z.url(),
  platform: z.enum(['reddit', 'telegram', 'discord', 'web']),
  title: z.string().optional(),
  snippet: z.string().optional(),
  matchedImageUrl: z.url().optional(),
  similarity: z.number().min(0).max(1).optional(),
  verification: z.enum(['verified', 'possible', 'unverified']),
  source: z.enum(['search', 'fetch']),
});
export type CandidateMatch = z.infer<typeof CandidateMatchSchema>;

/** Host attribution and abuse-contact information with supporting sources. */
export const HostRecordSchema = z.object({
  domain: z.string(),
  registrar: z.string().optional(),
  createdAt: z.string().optional(),
  hostingProvider: z.string().optional(),
  ip: z.string().optional(),
  abuseEmail: z.string().optional(),
  abuseFormUrl: z.string().optional(),
  sources: z.array(z.string()),
  error: z.string().optional(),
});
export type HostRecord = z.infer<typeof HostRecordSchema>;

/** Search and host investigation results, including errors and mock provenance. */
export const OsintResultSchema = z.object({
  query: z.string(),
  candidates: z.array(CandidateMatchSchema),
  hosts: z.array(HostRecordSchema),
  errors: z.array(z.string()),
  isMock: z.boolean(),
});
export type OsintResult = z.infer<typeof OsintResultSchema>;

/** An abuse reporting destination and the sources supporting that destination. */
export const AbuseContactSchema = z.object({
  domain: z.string(),
  email: z.string().optional(),
  formUrl: z.string().optional(),
  sources: z.array(z.string()),
});
export type AbuseContact = z.infer<typeof AbuseContactSchema>;

/** Tool execution metadata; notes must never contain image bytes or base64. */
export const ToolCallRecordSchema = z.object({
  tool: z.string(),
  at: z.iso.datetime({ offset: true }),
  ok: z.boolean(),
  note: z.string().optional(),
});
export type ToolCallRecord = z.infer<typeof ToolCallRecordSchema>;

/** Consolidated investigation findings, evidence, actions, and mock provenance. */
export const InvestigationReportSchema = z.object({
  caseId: z.uuid(),
  imageHash: z.string(),
  blocked: z.boolean(),
  riskLevel: z.enum(['low', 'medium', 'high']),
  findings: z.array(z.string()),
  matches: z.array(CandidateMatchSchema),
  hosts: z.array(HostRecordSchema),
  abuseContacts: z.array(AbuseContactSchema),
  evidenceList: z.array(z.string()),
  recommendedActions: z.array(z.string()),
  toolCallsMade: z.array(ToolCallRecordSchema),
  isMock: z.boolean(),
  generatedAt: z.string(),
});
export type InvestigationReport = z.infer<typeof InvestigationReportSchema>;
