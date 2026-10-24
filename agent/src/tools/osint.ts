import { Buffer } from 'node:buffer';
import dns from 'node:dns/promises';
import net from 'node:net';
import {
  CandidateMatch,
  CandidateMatchSchema,
  HostRecord,
  HostRecordSchema,
  OsintResult,
  OsintResultSchema,
  POSSIBLE_MIN_SIMILARITY,
  VERIFIED_MIN_SIMILARITY,
} from '../types.js';
import { computePerceptualHash, hashSimilarity, wipeBuffer } from './imageAnalysis.js';

/** Base error for all TinyFish client operations. */
export class TinyFishError extends Error {
  override readonly name: string = 'TinyFishError';
}

/** Authentication failed (HTTP 401). */
export class TinyFishAuthError extends TinyFishError {
  override readonly name: string = 'TinyFishAuthError';
}

/** Payment required or plan quota exceeded (HTTP 402). */
export class TinyFishQuotaError extends TinyFishError {
  override readonly name: string = 'TinyFishQuotaError';
}

/** Rate limit exceeded and retries exhausted (HTTP 429). */
export class TinyFishRateLimitError extends TinyFishError {
  override readonly name: string = 'TinyFishRateLimitError';
}

/** Request blocked due to SSRF protection on private/loopback/link-local address. */
export class SsrfBlockError extends Error {
  override readonly name = 'SsrfBlockError';
}

/** Image download or validation failure (non-image, oversized, network). */
export class ImageDownloadError extends Error {
  override readonly name = 'ImageDownloadError';
}

/** Single item in search response. */
export interface TinyFishSearchResultItem {
  url: string;
  title?: string;
  snippet?: string;
  imageUrl?: string;
}

/** Single page result in fetchPages response. */
export interface TinyFishFetchedPage {
  url: string;
  title?: string;
  snippet?: string;
  markdown?: string;
  imageLinks?: string[];
}

/**
 * Token bucket rate limiter supporting a max capacity and refill rate.
 * Default: 30 searches per minute (1 token per 2000 ms).
 */
export class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefill: number;
  readonly capacity: number;
  readonly refillIntervalMs: number;

  constructor(capacity = 30, perDurationMs = 60_000) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillIntervalMs = perDurationMs / capacity;
    this.lastRefill = Date.now();
  }

  /** Refill available tokens based on elapsed wall time. */
  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    if (elapsed > 0) {
      const added = elapsed / this.refillIntervalMs;
      this.tokens = Math.min(this.capacity, this.tokens + added);
      this.lastRefill = now;
    }
  }

  /** Check current tokens without waiting. */
  getAvailableTokens(): number {
    this.refill();
    return this.tokens;
  }

  /**
   * Acquire one or more tokens, waiting if current capacity is insufficient.
   */
  async acquire(tokens = 1): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= tokens) {
        this.tokens -= tokens;
        return;
      }
      const deficit = tokens - this.tokens;
      const waitMs = Math.max(10, Math.ceil(deficit * this.refillIntervalMs));
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }
  }

  /** Reset bucket to full capacity. */
  reset(): void {
    this.tokens = this.capacity;
    this.lastRefill = Date.now();
  }
}

/** Shared singleton rate limiter for TinyFish searches (30 searches / min). */
export const globalTinyFishRateLimiter = new TokenBucketRateLimiter(30, 60_000);

/** Determine if mock mode is active (via USE_MOCKS=true or missing API key). */
export function isMockMode(): boolean {
  if (process.env.USE_MOCKS === 'true') {
    return true;
  }
  const key = process.env.TINYFISH_API_KEY?.trim();
  return !key;
}

/**
 * TinyFish API client for search and page fetching with rate limiting,
 * exponential backoff retry on 429/503, typed auth/quota errors, and 20s timeouts.
 */
export class TinyFishClient {
  readonly apiKey: string;
  readonly searchUrl: string;
  readonly fetchUrl: string;
  readonly rateLimiter: TokenBucketRateLimiter;

  constructor(opts?: {
    apiKey?: string;
    searchUrl?: string;
    fetchUrl?: string;
    rateLimiter?: TokenBucketRateLimiter;
  }) {
    this.apiKey = opts?.apiKey?.trim() ?? process.env.TINYFISH_API_KEY?.trim() ?? '';
    this.searchUrl =
      opts?.searchUrl?.trim() ??
      process.env.TINYFISH_SEARCH_URL?.trim() ??
      'https://api.search.tinyfish.ai';
    this.fetchUrl =
      opts?.fetchUrl?.trim() ??
      process.env.TINYFISH_FETCH_URL?.trim() ??
      'https://api.fetch.tinyfish.ai';
    this.rateLimiter = opts?.rateLimiter ?? globalTinyFishRateLimiter;
  }

  /**
   * Perform fetch with timeout (20s) and retry with exponential backoff on 429/503.
   * Throws TinyFishAuthError on 401 and TinyFishQuotaError on 402.
   */
  private async fetchWithRetry(url: string, init: RequestInit, maxRetries = 3): Promise<Response> {
    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20_000);
      let response: Response;
      try {
        response = await fetch(url, {
          ...init,
          signal: controller.signal,
        });
      } catch (err: unknown) {
        clearTimeout(timeoutId);
        if (err instanceof Error && err.name === 'AbortError') {
          throw new TinyFishError('TinyFish request timed out after 20s');
        }
        throw new TinyFishError(
          `TinyFish network request failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      clearTimeout(timeoutId);

      if (response.ok) {
        return response;
      }

      if (response.status === 401) {
        throw new TinyFishAuthError('TinyFish authentication failed (401): invalid or missing API key');
      }

      if (response.status === 402) {
        throw new TinyFishQuotaError(
          'TinyFish quota exceeded (402): active plan or payment required',
        );
      }

      if (response.status === 429 || response.status === 503) {
        if (attempt < maxRetries) {
          attempt += 1;
          let delayMs = 150 * 2 ** (attempt - 1) + Math.random() * 50;
          const retryAfter = response.headers.get('Retry-After');
          if (retryAfter) {
            const parsed = Number(retryAfter);
            if (!Number.isNaN(parsed) && parsed > 0) {
              delayMs = parsed * 1000;
            }
          }
          await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
          continue;
        }

        if (response.status === 429) {
          throw new TinyFishRateLimitError('TinyFish rate limit exceeded after maximum retries (429)');
        }
        throw new TinyFishError('TinyFish service unavailable after maximum retries (503)');
      }

      throw new TinyFishError(
        `TinyFish request failed with HTTP ${response.status}: ${response.statusText}`,
      );
    }
  }

  /**
   * Search for query across indexed pages, respecting rate limiter.
   */
  async search(
    query: string,
    opts?: { includeDomains?: string[]; page?: number },
  ): Promise<TinyFishSearchResultItem[]> {
    if (isMockMode()) {
      return this.mockSearch(query, opts);
    }

    await this.rateLimiter.acquire();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const payload: Record<string, unknown> = {
      query,
      page: opts?.page ?? 1,
    };
    if (opts?.includeDomains && opts.includeDomains.length > 0) {
      payload['include_domains'] = opts.includeDomains;
    }

    const response = await this.fetchWithRetry(this.searchUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });

    const data = (await response.json()) as unknown;
    return this.parseSearchResults(data);
  }

  /**
   * Fetch rendered pages in batches of <= 10.
   */
  async fetchPages(
    urls: string[],
    opts?: { format?: string; imageLinks?: boolean; pageMetadata?: boolean },
  ): Promise<TinyFishFetchedPage[]> {
    if (urls.length === 0) {
      return [];
    }

    if (isMockMode()) {
      return this.mockFetchPages(urls);
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const results: TinyFishFetchedPage[] = [];
    // Batches of <= 10
    for (let i = 0; i < urls.length; i += 10) {
      const batch = urls.slice(i, i + 10);
      const payload = {
        urls: batch,
        format: opts?.format ?? 'markdown',
        image_links: opts?.imageLinks ?? true,
        page_metadata: opts?.pageMetadata ?? true,
      };

      const response = await this.fetchWithRetry(this.fetchUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });

      const data = (await response.json()) as unknown;
      results.push(...this.parseFetchedPages(data, batch));
    }

    return results;
  }

  /** Parse search API output formats gracefully. */
  private parseSearchResults(data: unknown): TinyFishSearchResultItem[] {
    const list: unknown[] = Array.isArray(data)
      ? data
      : typeof data === 'object' && data !== null && 'results' in data && Array.isArray((data as { results: unknown }).results)
        ? (data as { results: unknown[] }).results
        : typeof data === 'object' && data !== null && 'matches' in data && Array.isArray((data as { matches: unknown }).matches)
          ? (data as { matches: unknown[] }).matches
          : typeof data === 'object' && data !== null && 'data' in data && Array.isArray((data as { data: unknown }).data)
            ? (data as { data: unknown[] }).data
            : [];

    const items: TinyFishSearchResultItem[] = [];
    for (const item of list) {
      if (typeof item === 'object' && item !== null && 'url' in item && typeof (item as { url: unknown }).url === 'string') {
        const cast = item as Record<string, unknown>;
        const title = typeof cast['title'] === 'string' ? cast['title'] : undefined;
        const snippet = typeof cast['snippet'] === 'string' ? cast['snippet'] : undefined;
        const imageUrl =
          typeof cast['imageUrl'] === 'string'
            ? cast['imageUrl']
            : typeof cast['image_url'] === 'string'
              ? cast['image_url']
              : typeof cast['image'] === 'string'
                ? cast['image']
                : undefined;

        items.push({
          url: cast['url'] as string,
          ...(title ? { title } : {}),
          ...(snippet ? { snippet } : {}),
          ...(imageUrl ? { imageUrl } : {}),
        });
      }
    }
    return items;
  }

  /** Parse batch fetch API output formats. */
  private parseFetchedPages(data: unknown, requestedUrls: string[]): TinyFishFetchedPage[] {
    const pages: unknown[] = Array.isArray(data)
      ? data
      : typeof data === 'object' && data !== null && 'pages' in data && Array.isArray((data as { pages: unknown }).pages)
        ? (data as { pages: unknown[] }).pages
        : typeof data === 'object' && data !== null && 'results' in data && Array.isArray((data as { results: unknown }).results)
          ? (data as { results: unknown[] }).results
          : [];

    const results: TinyFishFetchedPage[] = [];
    for (const page of pages) {
      if (typeof page === 'object' && page !== null && 'url' in page && typeof (page as { url: unknown }).url === 'string') {
        const cast = page as Record<string, unknown>;
        const title =
          typeof cast['title'] === 'string'
            ? cast['title']
            : typeof cast['metadata'] === 'object' &&
                cast['metadata'] !== null &&
                'title' in (cast['metadata'] as Record<string, unknown>) &&
                typeof (cast['metadata'] as Record<string, unknown>)['title'] === 'string'
              ? ((cast['metadata'] as Record<string, unknown>)['title'] as string)
              : undefined;

        const snippet =
          typeof cast['snippet'] === 'string'
            ? cast['snippet']
            : typeof cast['description'] === 'string'
              ? cast['description']
              : undefined;

        const markdown = typeof cast['markdown'] === 'string' ? cast['markdown'] : undefined;

        const rawImages = cast['imageLinks'] ?? cast['image_links'] ?? cast['images'];
        const imageLinks: string[] = [];
        if (Array.isArray(rawImages)) {
          for (const img of rawImages) {
            if (typeof img === 'string') {
              imageLinks.push(img);
            }
          }
        }

        results.push({
          url: cast['url'] as string,
          ...(title ? { title } : {}),
          ...(snippet ? { snippet } : {}),
          ...(markdown ? { markdown } : {}),
          ...(imageLinks.length > 0 ? { imageLinks } : {}),
        });
      }
    }

    // Ensure all requested URLs get at least an entry
    for (const url of requestedUrls) {
      if (!results.some((r) => r.url === url)) {
        results.push({ url });
      }
    }

    return results;
  }

  /** Generate deterministic realistic mock search items on *.example domains. */
  private mockSearch(
    query: string,
    opts?: { includeDomains?: string[] },
  ): TinyFishSearchResultItem[] {
    const slug = query
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 24);

    const targetDomain = opts?.includeDomains?.[0]?.toLowerCase();

    if (targetDomain?.includes('reddit')) {
      return [
        {
          url: `https://reddit.example/r/imageleaks/comments/9021/${slug}`,
          title: `Reddit post discussion for ${query}`,
          snippet: `User thread referencing uploaded media in community discussion.`,
          imageUrl: `https://cdn.reddit.example/media/${slug}-thumb.png`,
        },
      ];
    }

    if (targetDomain?.includes('t.me') || targetDomain?.includes('telegram')) {
      return [
        {
          url: `https://t.me.example/leakchannel/4092/${slug}`,
          title: `Telegram Channel broadcast: ${query}`,
          snippet: `Public channel message containing image attachment.`,
          imageUrl: `https://cdn.t.me.example/files/${slug}-img.jpg`,
        },
      ];
    }

    if (targetDomain?.includes('discord')) {
      return [
        {
          url: `https://discord.example/channels/98124012/82103/${slug}`,
          title: `Discord archive match: ${query}`,
          snippet: `Server archive thread matching visual description terms.`,
          imageUrl: `https://cdn.discord.example/attachments/${slug}.webp`,
        },
      ];
    }

    // Default open web search
    return [
      {
        url: `https://mirror-1.example/threads/${slug}-4912`,
        title: `Mirror Index: ${query}`,
        snippet: `Public index mirror containing matching scene composition and re-upload notice.`,
        imageUrl: `https://cdn.mirror-1.example/photos/${slug}-photo.jpg`,
      },
      {
        url: `https://host-storage.example/galleries/${slug}`,
        title: `Public gallery view: ${query}`,
        snippet: `Gallery host directory page listing photo assets and metadata.`,
        imageUrl: `https://cdn.host-storage.example/cdn/${slug}-full.jpg`,
      },
    ];
  }

  /** Return mock fetched page details with realistic markdown and image links. */
  private mockFetchPages(urls: string[]): TinyFishFetchedPage[] {
    return urls.map((url, idx) => {
      let host = 'mirror.example';
      try {
        host = new URL(url).hostname;
      } catch {
        // use default
      }
      return {
        url,
        title: `Public Page on ${host}`,
        snippet: `Extracted content and media metadata for investigation report.`,
        markdown: `# Investigation Evidence\n\nDiscovered public media asset hosted on ${host}.`,
        imageLinks: [
          `https://cdn.${host}/images/evidence-${idx + 1}.jpg`,
        ],
      };
    });
  }
}

/**
 * Normalize a URL for consistent deduplication and comparison:
 * - Lowercases scheme and hostname
 * - Drops default ports (80/443)
 * - Drops URL fragment
 * - Removes standard tracking query parameters (utm_*, fbclid, gclid, etc.)
 * - Sorts query parameters
 * - Strips trailing slash on root paths
 */
export function normalizeUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  const parsed = new URL(trimmed);

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname = parsed.hostname.toLowerCase();

  if (
    (parsed.protocol === 'http:' && parsed.port === '80') ||
    (parsed.protocol === 'https:' && parsed.port === '443')
  ) {
    parsed.port = '';
  }

  parsed.hash = '';

  const trackingParams = new Set([
    'utm_source',
    'utm_medium',
    'utm_campaign',
    'utm_term',
    'utm_content',
    'utm_id',
    'fbclid',
    'gclid',
    'igshid',
    'ref',
    'ref_src',
  ]);

  const searchParams = new URLSearchParams();
  const keys = Array.from(parsed.searchParams.keys()).sort();
  for (const key of keys) {
    if (!trackingParams.has(key.toLowerCase())) {
      const values = parsed.searchParams.getAll(key);
      for (const val of values) {
        searchParams.append(key, val);
      }
    }
  }

  parsed.search = searchParams.toString() ? `?${searchParams.toString()}` : '';

  let normalized = parsed.toString();
  if (normalized.endsWith('/') && parsed.pathname === '/') {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

/**
 * Classify a URL platform into 'reddit' | 'telegram' | 'discord' | 'web'.
 */
export function classifyPlatform(url: string): 'reddit' | 'telegram' | 'discord' | 'web' {
  try {
    const { hostname } = new URL(url);
    const host = hostname.toLowerCase();

    if (
      host === 'reddit.com' ||
      host.endsWith('.reddit.com') ||
      host === 'redd.it' ||
      host.endsWith('.redd.it')
    ) {
      return 'reddit';
    }

    if (
      host === 't.me' ||
      host.endsWith('.t.me') ||
      host === 'telegram.me' ||
      host.endsWith('.telegram.me') ||
      host === 'telegram.org' ||
      host.endsWith('.telegram.org')
    ) {
      return 'telegram';
    }

    if (
      host === 'discord.com' ||
      host.endsWith('.discord.com') ||
      host === 'discord.gg' ||
      host.endsWith('.discord.gg') ||
      host === 'discordapp.com' ||
      host.endsWith('.discordapp.com')
    ) {
      return 'discord';
    }

    return 'web';
  } catch {
    return 'web';
  }
}

/**
 * Execute searches across open web, reddit, telegram, and discord.
 * Concurrency limited to 3 queries, candidates capped at 30 per query, deduplicated by normalized URL.
 */
export async function searchCandidates(
  queries: string[],
  client = new TinyFishClient(),
): Promise<CandidateMatch[]> {
  const candidateMap = new Map<string, CandidateMatch>();

  // Concurrency limit of 3 queries
  const concurrency = 3;
  for (let i = 0; i < queries.length; i += concurrency) {
    const batch = queries.slice(i, i + concurrency);
    await Promise.all(
      batch.map(async (query) => {
        let perQueryCount = 0;
        const targets: Array<{ includeDomains?: string[] }> = [
          {}, // open web
          { includeDomains: ['reddit.com'] },
          { includeDomains: ['t.me'] },
          { includeDomains: ['discord.com'] },
        ];

        for (const target of targets) {
          if (perQueryCount >= 30) break;
          try {
            const items = await client.search(query, target);
            for (const item of items) {
              if (perQueryCount >= 30) break;
              try {
                const normalized = normalizeUrl(item.url);
                if (!candidateMap.has(normalized)) {
                  const candidate: CandidateMatch = {
                    url: normalized,
                    platform: classifyPlatform(normalized),
                    verification: 'unverified',
                    source: 'search',
                    ...(item.title ? { title: item.title } : {}),
                    ...(item.snippet ? { snippet: item.snippet } : {}),
                    ...(item.imageUrl ? { matchedImageUrl: item.imageUrl } : {}),
                  };
                  candidateMap.set(normalized, CandidateMatchSchema.parse(candidate));
                  perQueryCount += 1;
                }
              } catch {
                // Ignore invalid URL candidates
              }
            }
          } catch {
            // Tolerate individual target failures, continue search
          }
        }
      }),
    );
  }

  return Array.from(candidateMap.values());
}

/**
 * Enrich discovered candidates using TinyFish fetchPages to extract page metadata,
 * titles, snippets, and image links.
 */
export async function enrichCandidates(
  candidates: CandidateMatch[],
  client = new TinyFishClient(),
): Promise<CandidateMatch[]> {
  if (candidates.length === 0) {
    return [];
  }

  const urls = candidates.map((c) => c.url);
  const fetchedPages = await client.fetchPages(urls, {
    format: 'markdown',
    imageLinks: true,
    pageMetadata: true,
  });

  const pageByUrl = new Map<string, TinyFishFetchedPage>();
  for (const page of fetchedPages) {
    try {
      pageByUrl.set(normalizeUrl(page.url), page);
    } catch {
      pageByUrl.set(page.url, page);
    }
  }

  return candidates.map((candidate) => {
    const page = pageByUrl.get(candidate.url) ?? pageByUrl.get(candidate.url);
    if (!page) {
      return candidate;
    }

    const title = page.title || candidate.title;
    const snippet = page.snippet || (page.markdown ? page.markdown.slice(0, 200).trim() : candidate.snippet);
    const matchedImageUrl =
      candidate.matchedImageUrl ||
      (page.imageLinks && page.imageLinks.length > 0 ? page.imageLinks[0] : undefined);

    const enriched: CandidateMatch = {
      ...candidate,
      source: 'fetch',
      ...(title ? { title } : {}),
      ...(snippet ? { snippet } : {}),
      ...(matchedImageUrl ? { matchedImageUrl } : {}),
    };

    return CandidateMatchSchema.parse(enriched);
  });
}

/**
 * Check if an IP address is a private, loopback, link-local, carrier-grade NAT,
 * multicast, or reserved address to prevent SSRF vulnerabilities.
 */
export function isDisallowedIp(ipStr: string): boolean {
  const ip = ipStr.trim().toLowerCase();

  // IPv4 validation
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map((p) => Number(p));
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
      return true;
    }
    const [a, b, c] = parts as [number, number, number, number];

    // 0.0.0.0/8 (Current network)
    if (a === 0) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 100.64.0.0/10 (Carrier-grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 169.254.0.0/16 (Link-local / Cloud metadata)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (Private: 172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments) and 192.0.2.0/24 (TEST-NET-1)
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 198.18.0.0/15 (Benchmarking: 198.18.0.0 - 198.19.255.255)
    if (a === 198 && (b === 18 || b === 19)) return true;
    // 198.51.100.0/24 (TEST-NET-2)
    if (a === 198 && b === 51 && c === 100) return true;
    // 203.0.113.0/24 (TEST-NET-3)
    if (a === 203 && b === 0 && c === 113) return true;
    // 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
    if (a >= 224 && a <= 239) return true;
    // 240.0.0.0/4 (Reserved / Broadcast: 240.0.0.0 - 255.255.255.255)
    if (a >= 240) return true;

    return false;
  }

  // IPv6 validation
  if (net.isIPv6(ip)) {
    // Check IPv4-mapped IPv6 address, e.g. ::ffff:192.168.1.1
    if (ip.startsWith('::ffff:')) {
      const remaining = ip.slice(7);
      if (net.isIPv4(remaining)) {
        return isDisallowedIp(remaining);
      }
    }
    // Loopback ::1 and unspecified ::
    if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:1' || ip === '0:0:0:0:0:0:0:0') {
      return true;
    }
    // Link-local: fe80::/10 (fe8, fe9, fea, feb)
    if (/^fe[89ab]/i.test(ip)) return true;
    // Unique local address: fc00::/7 (fc or fd)
    if (/^f[cd]/i.test(ip)) return true;
    // Multicast: ff00::/8
    if (/^ff/i.test(ip)) return true;
    // Documentation: 2001:db8::/32
    if (/^2001:0?db8:/i.test(ip)) return true;

    return false;
  }

  // Unrecognized IP format -> block
  return true;
}

const MAX_IMAGE_DOWNLOAD_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Safely download an image in memory with:
 * - Scheme restriction (http/https only)
 * - Strict DNS resolution SSRF blocking (private/loopback/link-local)
 * - Content-Type validation (image/*)
 * - Maximum 5MB size limit (checked on headers and streaming chunks)
 * - In-memory only (never persisted to disk)
 */
export async function downloadImageSafely(imageUrl: string): Promise<Buffer> {
  let parsed: URL;
  try {
    parsed = new URL(imageUrl);
  } catch {
    throw new ImageDownloadError('Invalid image URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SsrfBlockError(`SSRF blocked: protocol ${parsed.protocol} is not supported`);
  }

  const hostname = parsed.hostname;

  // DNS lookup to verify every resolved address
  let lookupResults: Array<{ address: string; family: number }>;
  try {
    lookupResults = await dns.lookup(hostname, { all: true });
  } catch (err: unknown) {
    throw new ImageDownloadError(
      `DNS lookup failed for ${hostname}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (lookupResults.length === 0) {
    throw new ImageDownloadError(`No DNS addresses resolved for host ${hostname}`);
  }

  for (const { address } of lookupResults) {
    if (isDisallowedIp(address)) {
      throw new SsrfBlockError(
        `SSRF blocked: host ${hostname} resolved to private/loopback/link-local address ${address}`,
      );
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  let response: Response;
  try {
    response = await fetch(imageUrl, {
      signal: controller.signal,
      headers: {
        Accept: 'image/jpeg,image/png,image/webp,image/*;q=0.8',
      },
    });
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof Error && err.name === 'AbortError') {
      throw new ImageDownloadError('Image download timed out after 10s');
    }
    throw new ImageDownloadError(
      `Image download failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new ImageDownloadError(`Image download failed with status ${response.status}`);
  }

  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('image/')) {
    throw new ImageDownloadError(`Invalid image Content-Type: ${contentType || 'missing'}`);
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength) {
    const length = Number(contentLength);
    if (!Number.isNaN(length) && length > MAX_IMAGE_DOWNLOAD_BYTES) {
      throw new ImageDownloadError(`Image size (${length} bytes) exceeds 5MB limit`);
    }
  }

  const reader = response.body?.getReader();
  if (!reader) {
    const arrayBuf = await response.arrayBuffer();
    if (arrayBuf.byteLength > MAX_IMAGE_DOWNLOAD_BYTES) {
      throw new ImageDownloadError('Image size exceeds 5MB limit');
    }
    return Buffer.from(arrayBuf);
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      totalBytes += value.length;
      if (totalBytes > MAX_IMAGE_DOWNLOAD_BYTES) {
        await reader.cancel();
        throw new ImageDownloadError('Image stream exceeded 5MB limit');
      }
      chunks.push(value);
    }
  }

  return Buffer.concat(chunks);
}

/**
 * Verify candidate matches by comparing perceptual hash (dHash) against the original image.
 * Sets verification:
 * - 'verified' if similarity >= 0.90 (VERIFIED_MIN_SIMILARITY)
 * - 'possible' if similarity >= 0.75 (POSSIBLE_MIN_SIMILARITY)
 * - 'unverified' otherwise
 */
export async function verifyCandidates(
  candidates: CandidateMatch[],
  originalImageBuffer?: Buffer,
): Promise<CandidateMatch[]> {
  if (!originalImageBuffer || candidates.length === 0) {
    return candidates;
  }

  const originalHash = await computePerceptualHash(originalImageBuffer);

  const verifiedList: CandidateMatch[] = [];

  for (const candidate of candidates) {
    if (!candidate.matchedImageUrl) {
      verifiedList.push(candidate);
      continue;
    }

    // In mock mode with .example domains, provide deterministic mock similarity if download cannot occur
    if (isMockMode() && candidate.matchedImageUrl.includes('.example')) {
      const sim = 0.92;
      const verified: CandidateMatch = {
        ...candidate,
        similarity: sim,
        verification:
          sim >= VERIFIED_MIN_SIMILARITY
            ? 'verified'
            : sim >= POSSIBLE_MIN_SIMILARITY
              ? 'possible'
              : 'unverified',
      };
      verifiedList.push(CandidateMatchSchema.parse(verified));
      continue;
    }

    let candidateBuf: Buffer | undefined;
    try {
      candidateBuf = await downloadImageSafely(candidate.matchedImageUrl);
      const candidateHash = await computePerceptualHash(candidateBuf);
      const similarity = hashSimilarity(originalHash, candidateHash);

      const status: 'verified' | 'possible' | 'unverified' =
        similarity >= VERIFIED_MIN_SIMILARITY
          ? 'verified'
          : similarity >= POSSIBLE_MIN_SIMILARITY
            ? 'possible'
            : 'unverified';

      const updated: CandidateMatch = {
        ...candidate,
        similarity,
        verification: status,
      };
      verifiedList.push(CandidateMatchSchema.parse(updated));
    } catch {
      // Keep candidate as unverified if download or hashing fails
      verifiedList.push(candidate);
    } finally {
      if (candidateBuf) {
        wipeBuffer(candidateBuf);
      }
    }
  }

  return verifiedList;
}

/**
 * Extract jCard contact values for a field (e.g. 'fn', 'org', 'email') from an RDAP entity.
 */
function extractVCardProperty(entity: Record<string, unknown>, propName: string): string[] {
  const vcard = entity['vcardArray'];
  if (!Array.isArray(vcard) || vcard.length < 2 || !Array.isArray(vcard[1])) {
    return [];
  }
  const results: string[] = [];
  for (const entry of vcard[1]) {
    if (Array.isArray(entry) && entry.length >= 4 && entry[0] === propName) {
      const val = entry[3];
      if (typeof val === 'string' && val.trim()) {
        results.push(val.trim());
      }
    }
  }
  return results;
}

/** Known CDN identifiers for hosting provider annotation. */
const KNOWN_CDNS = [
  { name: 'Cloudflare', pattern: /cloudflare/i },
  { name: 'AWS CloudFront', pattern: /cloudfront|amazon/i },
  { name: 'Fastly', pattern: /fastly/i },
  { name: 'Akamai', pattern: /akamai/i },
];

/**
 * Perform concurrent RDAP and DNS host lookups with concurrency limit of 5 and 8s timeout.
 * Extracts registrar, creation date, abuse emails, hosting provider, and CDN notes.
 */
export async function lookupHosts(domains: string[]): Promise<Map<string, HostRecord>> {
  const uniqueDomains = Array.from(new Set(domains.map((d) => d.trim().toLowerCase()))).filter(
    (d) => d.length > 0,
  );

  const results = new Map<string, HostRecord>();
  if (uniqueDomains.length === 0) {
    return results;
  }

  // Concurrency limit of 5
  const concurrency = 5;
  for (let i = 0; i < uniqueDomains.length; i += concurrency) {
    const batch = uniqueDomains.slice(i, i + concurrency);
    const settled = await Promise.all(
      batch.map(async (domain): Promise<[string, HostRecord]> => {
        // Mock mode or reserved .example domain
        if (isMockMode() || domain.endsWith('.example')) {
          const mockRecord: HostRecord = {
            domain,
            registrar: 'Example Registrar LLC',
            createdAt: '2021-04-12T00:00:00Z',
            hostingProvider: 'Example Cloud Services (CDN: Cloudflare)',
            ip: '93.184.216.34',
            abuseEmail: `abuse@${domain}`,
            abuseFormUrl: `https://${domain}/abuse-reports`,
            sources: [`https://rdap.org/domain/${domain}`, 'dns:resolve'],
          };
          return [domain, HostRecordSchema.parse(mockRecord)];
        }

        const sources: string[] = [`https://rdap.org/domain/${domain}`];
        let registrar: string | undefined;
        let createdAt: string | undefined;
        let abuseEmail: string | undefined;
        let abuseFormUrl: string | undefined;
        let hostingProvider: string | undefined;
        let ip: string | undefined;
        let lookupError: string | undefined;

        // 1. DNS Resolution (IP lookup) with 8s timeout
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 8000);
          const addresses = await dns.resolve4(domain);
          clearTimeout(timer);
          if (addresses.length > 0 && addresses[0]) {
            ip = addresses[0];
            sources.push('dns:resolve4');
          }
        } catch {
          // IP resolution might fail; continue with RDAP
        }

        // 2. RDAP Lookup with 8s timeout
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 8000);
          const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
            headers: {
              Accept: 'application/rdap+json, application/json',
            },
            signal: controller.signal,
          });
          clearTimeout(timer);

          if (!response.ok) {
            lookupError = `RDAP lookup returned HTTP ${response.status}`;
          } else {
            const data = (await response.json()) as Record<string, unknown>;

            // Parse createdAt from events
            const events = data['events'];
            if (Array.isArray(events)) {
              for (const evt of events) {
                if (
                  typeof evt === 'object' &&
                  evt !== null &&
                  'eventAction' in evt &&
                  ('eventDate' in evt || 'date' in evt)
                ) {
                  const action = (evt as { eventAction: unknown }).eventAction;
                  if (action === 'registration' || action === 'created') {
                    const dateVal =
                      (evt as { eventDate?: unknown }).eventDate ??
                      (evt as { date?: unknown }).date;
                    if (typeof dateVal === 'string') {
                      createdAt = dateVal;
                      break;
                    }
                  }
                }
              }
            }

            // Parse entities (registrar and abuse) using a queue to traverse nested entities
            const entities = data['entities'];
            if (Array.isArray(entities)) {
              const queue: unknown[] = [...entities];
              let visited = 0;
              while (queue.length > 0 && visited < 500) {
                visited += 1;
                const ent = queue.pop();
                if (typeof ent !== 'object' || ent === null) continue;
                const cast = ent as Record<string, unknown>;
                const roles = cast['roles'];

                if (Array.isArray(roles)) {
                  if (roles.includes('registrar') && !registrar) {
                    const names =
                      extractVCardProperty(cast, 'fn') || extractVCardProperty(cast, 'org');
                    if (names.length > 0 && names[0]) {
                      registrar = names[0];
                    }
                  }
                  if (roles.includes('abuse') && !abuseEmail) {
                    const emails = extractVCardProperty(cast, 'email');
                    if (emails.length > 0 && emails[0]) {
                      abuseEmail = emails[0];
                    }
                  }
                }

                // Nested entities
                const subEntities = cast['entities'];
                if (Array.isArray(subEntities)) {
                  queue.push(...subEntities);
                }
              }
            }

            // Detect CDN notes in registrar or links
            for (const cdn of KNOWN_CDNS) {
              if (
                (registrar && cdn.pattern.test(registrar)) ||
                cdn.pattern.test(domain)
              ) {
                hostingProvider = `${registrar ?? 'CDN Host'} (CDN: ${cdn.name})`;
                break;
              }
            }

            if (!hostingProvider && registrar) {
              hostingProvider = `Registrar: ${registrar}`;
            }

            // Extract abuse form URL from links if available
            const links = data['links'];
            if (Array.isArray(links)) {
              for (const link of links) {
                if (typeof link === 'object' && link !== null) {
                  const href = (link as { href?: unknown }).href;
                  if (typeof href === 'string' && /abuse/i.test(href)) {
                    abuseFormUrl = href;
                    break;
                  }
                }
              }
            }
          }
        } catch (err: unknown) {
          lookupError =
            err instanceof Error && err.name === 'AbortError'
              ? 'RDAP lookup timed out after 8s'
              : err instanceof Error
                ? err.message
                : String(err);
        }

        const hostRecord: HostRecord = {
          domain,
          sources,
          ...(registrar ? { registrar } : {}),
          ...(createdAt ? { createdAt } : {}),
          ...(hostingProvider ? { hostingProvider } : {}),
          ...(ip ? { ip } : {}),
          ...(abuseEmail ? { abuseEmail } : {}),
          ...(abuseFormUrl ? { abuseFormUrl } : {}),
          ...(lookupError ? { error: lookupError } : {}),
        };

        return [domain, HostRecordSchema.parse(hostRecord)];
      }),
    );

    for (const [domain, record] of settled) {
      results.set(domain, record);
    }
  }

  return results;
}

/**
 * High-level orchestration function:
 * Runs search -> enrichment -> perceptual hash verification -> RDAP host lookups.
 * Produces OsintResult for each query with full provenance and mock status.
 */
export async function runTinyFishSearch(
  queries: string[],
  opts?: { originalImageBuffer?: Buffer; client?: TinyFishClient },
): Promise<OsintResult[]> {
  const client = opts?.client ?? new TinyFishClient();
  const results: OsintResult[] = [];

  for (const query of queries) {
    const errors: string[] = [];
    let candidates: CandidateMatch[] = [];

    // Step 1: Search
    try {
      candidates = await searchCandidates([query], client);
    } catch (err: unknown) {
      errors.push(`Search failed for "${query}": ${err instanceof Error ? err.message : String(err)}`);
    }

    // Step 2: Enrich
    try {
      candidates = await enrichCandidates(candidates, client);
    } catch (err: unknown) {
      errors.push(`Enrichment failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Step 3: Verify
    try {
      candidates = await verifyCandidates(candidates, opts?.originalImageBuffer);
    } catch (err: unknown) {
      errors.push(`Verification failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Step 4: Host Lookup
    const hostDomains = new Set<string>();
    for (const c of candidates) {
      try {
        const host = new URL(c.url).hostname;
        if (host) hostDomains.add(host);
      } catch {
        // ignore malformed URLs
      }
    }

    let hostMap = new Map<string, HostRecord>();
    try {
      hostMap = await lookupHosts(Array.from(hostDomains));
    } catch (err: unknown) {
      errors.push(`Host lookup failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    const osintResult: OsintResult = {
      query,
      candidates,
      hosts: Array.from(hostMap.values()),
      errors,
      isMock: isMockMode(),
    };

    results.push(OsintResultSchema.parse(osintResult));
  }

  return results;
}
