import { Buffer } from 'node:buffer';
import dns from 'node:dns/promises';
import sharp from 'sharp';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CandidateMatchSchema,
  HostRecordSchema,
  OsintResultSchema,
  POSSIBLE_MIN_SIMILARITY,
  VERIFIED_MIN_SIMILARITY,
} from '../types.js';
import {
  ImageDownloadError,
  SsrfBlockError,
  TinyFishAuthError,
  TinyFishClient,
  TinyFishError,
  TinyFishQuotaError,
  TinyFishRateLimitError,
  TokenBucketRateLimiter,
  classifyPlatform,
  downloadImageSafely,
  enrichCandidates,
  isDisallowedIp,
  isMockMode,
  lookupHosts,
  normalizeUrl,
  runTinyFishSearch,
  searchCandidates,
  verifyCandidates,
} from './osint.js';

describe('normalizeUrl helper', () => {
  it('lowercases protocol and hostname', () => {
    expect(normalizeUrl('HTTPS://WWW.EXAMPLE.COM/Path/To/Page')).toBe(
      'https://www.example.com/Path/To/Page',
    );
  });

  it('removes default ports 80 and 443', () => {
    expect(normalizeUrl('http://example.com:80/path')).toBe('http://example.com/path');
    expect(normalizeUrl('https://example.com:443/path')).toBe('https://example.com/path');
    expect(normalizeUrl('https://example.com:8443/path')).toBe('https://example.com:8443/path');
  });

  it('drops hash fragments', () => {
    expect(normalizeUrl('https://example.com/page#section-3')).toBe('https://example.com/page');
  });

  it('strips tracking parameters and sorts query parameters', () => {
    const raw =
      'https://example.com/post?utm_source=twitter&b=2&utm_medium=cpc&a=1&fbclid=xyz&ref=partner';
    const normalized = normalizeUrl(raw);
    expect(normalized).toBe('https://example.com/post?a=1&b=2');
  });

  it('removes trailing slash on root path', () => {
    expect(normalizeUrl('https://example.com/')).toBe('https://example.com');
  });
});

describe('classifyPlatform helper', () => {
  it('identifies reddit URLs', () => {
    expect(classifyPlatform('https://reddit.com/r/pics/123')).toBe('reddit');
    expect(classifyPlatform('https://www.reddit.com/r/pics/123')).toBe('reddit');
    expect(classifyPlatform('https://old.reddit.com/r/pics/123')).toBe('reddit');
    expect(classifyPlatform('https://redd.it/xyz123')).toBe('reddit');
    expect(classifyPlatform('https://v.redd.it/abc456')).toBe('reddit');
  });

  it('identifies telegram URLs', () => {
    expect(classifyPlatform('https://t.me/channelname/102')).toBe('telegram');
    expect(classifyPlatform('https://telegram.me/joinchat/xxx')).toBe('telegram');
    expect(classifyPlatform('https://telegram.org/dl')).toBe('telegram');
  });

  it('identifies discord URLs', () => {
    expect(classifyPlatform('https://discord.com/channels/123/456')).toBe('discord');
    expect(classifyPlatform('https://discord.gg/invitelink')).toBe('discord');
    expect(classifyPlatform('https://discordapp.com/attachments/111/222')).toBe('discord');
  });

  it('defaults to web for standard sites and invalid inputs', () => {
    expect(classifyPlatform('https://example.com/image.jpg')).toBe('web');
    expect(classifyPlatform('https://pastebin.com/raw/abcd')).toBe('web');
    expect(classifyPlatform('not-a-valid-url')).toBe('web');
  });
});

describe('TokenBucketRateLimiter', () => {
  it('initializes to full capacity', () => {
    const limiter = new TokenBucketRateLimiter(10, 1000);
    expect(limiter.getAvailableTokens()).toBe(10);
  });

  it('consumes tokens on acquire', async () => {
    const limiter = new TokenBucketRateLimiter(5, 1000);
    await limiter.acquire(2);
    expect(limiter.getAvailableTokens()).toBeLessThanOrEqual(3.1);
    expect(limiter.getAvailableTokens()).toBeGreaterThanOrEqual(2.9);
  });

  it('delays when tokens are depleted and refills over time', async () => {
    // 2 tokens per 200ms -> 100ms per token
    const limiter = new TokenBucketRateLimiter(2, 200);
    await limiter.acquire(2);
    expect(limiter.getAvailableTokens()).toBeLessThan(1);

    const start = Date.now();
    await limiter.acquire(1);
    const elapsed = Date.now() - start;
    // Should have waited at least 50ms for refill
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });
});

describe('SSRF Protection (isDisallowedIp)', () => {
  it('blocks loopback IPv4 addresses', () => {
    expect(isDisallowedIp('127.0.0.1')).toBe(true);
    expect(isDisallowedIp('127.0.0.2')).toBe(true);
    expect(isDisallowedIp('127.255.255.254')).toBe(true);
  });

  it('blocks private 10.x.x.x addresses', () => {
    expect(isDisallowedIp('10.0.0.1')).toBe(true);
    expect(isDisallowedIp('10.254.12.3')).toBe(true);
  });

  it('blocks private 192.168.x.x addresses', () => {
    expect(isDisallowedIp('192.168.1.1')).toBe(true);
    expect(isDisallowedIp('192.168.0.254')).toBe(true);
  });

  it('blocks link-local / cloud metadata (169.254.x.x) addresses', () => {
    expect(isDisallowedIp('169.254.169.254')).toBe(true);
    expect(isDisallowedIp('169.254.1.1')).toBe(true);
  });

  it('blocks private 172.16.0.0 - 172.31.255.255 addresses', () => {
    expect(isDisallowedIp('172.16.0.1')).toBe(true);
    expect(isDisallowedIp('172.20.10.5')).toBe(true);
    expect(isDisallowedIp('172.31.255.255')).toBe(true);
    // Public 172 ranges should NOT be blocked
    expect(isDisallowedIp('172.15.255.255')).toBe(false);
    expect(isDisallowedIp('172.32.0.1')).toBe(false);
  });

  it('blocks carrier-grade NAT, multicast, reserved, and broadcast', () => {
    expect(isDisallowedIp('100.64.0.1')).toBe(true);
    expect(isDisallowedIp('100.127.255.254')).toBe(true);
    expect(isDisallowedIp('0.0.0.0')).toBe(true);
    expect(isDisallowedIp('224.0.0.1')).toBe(true); // multicast
    expect(isDisallowedIp('240.0.0.1')).toBe(true); // reserved
    expect(isDisallowedIp('255.255.255.255')).toBe(true); // broadcast
  });

  it('blocks loopback and link-local IPv6 addresses', () => {
    expect(isDisallowedIp('::1')).toBe(true);
    expect(isDisallowedIp('::')).toBe(true);
    expect(isDisallowedIp('fe80::1')).toBe(true); // link-local
    expect(isDisallowedIp('fc00::1')).toBe(true); // ULA
    expect(isDisallowedIp('fd12:3456:789a::1')).toBe(true); // ULA
    expect(isDisallowedIp('::ffff:127.0.0.1')).toBe(true); // IPv4-mapped loopback
    expect(isDisallowedIp('::ffff:192.168.1.1')).toBe(true); // IPv4-mapped private
  });

  it('permits valid public IP addresses', () => {
    expect(isDisallowedIp('93.184.216.34')).toBe(false); // example.com
    expect(isDisallowedIp('8.8.8.8')).toBe(false); // Google DNS
    expect(isDisallowedIp('1.1.1.1')).toBe(false); // Cloudflare DNS
    expect(isDisallowedIp('151.101.1.140')).toBe(false); // Fastly
    expect(isDisallowedIp('2606:4700:4700::1111')).toBe(false); // Cloudflare IPv6
  });
});

describe('downloadImageSafely SSRF and size bounds', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects unsupported protocols (ftp, file, javascript)', async () => {
    await expect(downloadImageSafely('ftp://example.com/test.png')).rejects.toBeInstanceOf(
      SsrfBlockError,
    );
    await expect(downloadImageSafely('file:///etc/passwd')).rejects.toBeInstanceOf(SsrfBlockError);
  });

  it('blocks domains resolving to private/loopback/cloud metadata IP', async () => {
    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '169.254.169.254', family: 4 },
    ] as never);

    await expect(
      downloadImageSafely('http://metadata.aws.internal/latest/meta-data/image.png'),
    ).rejects.toBeInstanceOf(SsrfBlockError);
  });

  it('blocks localhost or 127.0.0.1 resolutions', async () => {
    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '127.0.0.1', family: 4 },
    ] as never);

    await expect(downloadImageSafely('https://localhost:8080/image.jpg')).rejects.toBeInstanceOf(
      SsrfBlockError,
    );
  });

  it('rejects non-image content-type', async () => {
    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '93.184.216.34', family: 4 },
    ] as never);
    global.fetch = vi.fn().mockResolvedValue(
      new Response('<html><body>Not an image</body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      }),
    );

    await expect(downloadImageSafely('https://example.com/fake-image.jpg')).rejects.toBeInstanceOf(
      ImageDownloadError,
    );
  });

  it('rejects images exceeding 5MB via Content-Length', async () => {
    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '93.184.216.34', family: 4 },
    ] as never);
    global.fetch = vi.fn().mockResolvedValue(
      new Response(Buffer.alloc(100), {
        status: 200,
        headers: {
          'content-type': 'image/jpeg',
          'content-length': String(6 * 1024 * 1024), // 6MB
        },
      }),
    );

    await expect(downloadImageSafely('https://example.com/huge.jpg')).rejects.toBeInstanceOf(
      ImageDownloadError,
    );
  });

  it('downloads valid image safely into memory buffer', async () => {
    const samplePng = await sharp({
      create: { width: 10, height: 10, channels: 3, background: 'red' },
    })
      .png()
      .toBuffer();

    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '93.184.216.34', family: 4 },
    ] as never);
    global.fetch = vi.fn().mockResolvedValue(
      new Response(samplePng, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          'content-length': String(samplePng.length),
        },
      }),
    );

    const buf = await downloadImageSafely('https://example.com/valid.png');
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(samplePng.length);
  });
});

describe('TinyFishClient HTTP retry, rate limit, and error handling', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('USE_MOCKS', 'false');
    vi.stubEnv('TINYFISH_API_KEY', 'test-api-key');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('retries on 429 Too Many Requests and succeeds when upstream recovers', async () => {
    let callCount = 0;
    global.fetch = vi.fn().mockImplementation(() => {
      callCount += 1;
      if (callCount < 3) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: 'rate limited' }), {
            status: 429,
            headers: { 'Retry-After': '0.01' },
          }),
        );
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            results: [{ url: 'https://example.com/found-post', title: 'Found Title' }],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    });

    const client = new TinyFishClient({ apiKey: 'test-key' });
    const results = await client.search('leaked image query');

    expect(callCount).toBe(3);
    expect(results).toHaveLength(1);
    expect(results[0]?.url).toBe('https://example.com/found-post');
  });

  it('retries on 503 Service Unavailable and succeeds', async () => {
    let callCount = 0;
    global.fetch = vi.fn().mockImplementation(() => {
      callCount += 1;
      if (callCount < 2) {
        return Promise.resolve(
          new Response('Service Unavailable', { status: 503 }),
        );
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            results: [{ url: 'https://example.com/service-recovered' }],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    });

    const client = new TinyFishClient({ apiKey: 'test-key' });
    const results = await client.search('query after 503');

    expect(callCount).toBe(2);
    expect(results[0]?.url).toBe('https://example.com/service-recovered');
  });

  it('throws TinyFishRateLimitError after retries are exhausted on 429', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'Too many requests' }), {
        status: 429,
        headers: { 'Retry-After': '0.01' },
      }),
    );

    const client = new TinyFishClient({ apiKey: 'test-key' });
    await expect(client.search('rate limit test')).rejects.toBeInstanceOf(TinyFishRateLimitError);
  });

  it('throws TinyFishAuthError immediately on 401 Unauthorized without retrying', async () => {
    let callCount = 0;
    global.fetch = vi.fn().mockImplementation(() => {
      callCount += 1;
      return Promise.resolve(new Response('Unauthorized', { status: 401 }));
    });

    const client = new TinyFishClient({ apiKey: 'invalid-key' });
    await expect(client.search('auth test')).rejects.toBeInstanceOf(TinyFishAuthError);
    expect(callCount).toBe(1);
  });

  it('throws TinyFishQuotaError immediately on 402 Payment Required', async () => {
    let callCount = 0;
    global.fetch = vi.fn().mockImplementation(() => {
      callCount += 1;
      return Promise.resolve(new Response('Quota Exceeded', { status: 402 }));
    });

    const client = new TinyFishClient({ apiKey: 'exhausted-key' });
    await expect(client.search('quota test')).rejects.toBeInstanceOf(TinyFishQuotaError);
    expect(callCount).toBe(1);
  });

  it('splits fetchPages into batches of <= 10 URLs', async () => {
    const requestedUrls = Array.from({ length: 25 }, (_, i) => `https://example.com/page/${i + 1}`);
    const batchSizes: number[] = [];

    global.fetch = vi.fn().mockImplementation((_url, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { urls: string[] };
      batchSizes.push(body.urls.length);
      return Promise.resolve(
        new Response(
          JSON.stringify({
            pages: body.urls.map((u) => ({
              url: u,
              title: `Title for ${u}`,
              imageLinks: [`${u}/img.png`],
            })),
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    });

    const client = new TinyFishClient({ apiKey: 'test-key' });
    const pages = await client.fetchPages(requestedUrls);

    // 25 URLs split into batches of <= 10 -> [10, 10, 5]
    expect(batchSizes).toEqual([10, 10, 5]);
    expect(pages).toHaveLength(25);
  });
});

describe('RDAP Host Lookup Parsing', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('USE_MOCKS', 'false');
    vi.stubEnv('TINYFISH_API_KEY', 'test-api-key');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('extracts registrar, createdAt, abuseEmail, and sources from RDAP response', async () => {
    vi.spyOn(dns, 'resolve4').mockResolvedValue(['198.51.100.22']);

    const sampleRdap = {
      objectClassName: 'domain',
      handle: 'EXAMPLE-DOM',
      ldhName: 'targethost.org',
      events: [
        { eventAction: 'registration', eventDate: '2019-03-14T12:00:00Z' },
        { eventAction: 'last changed', eventDate: '2023-01-01T00:00:00Z' },
      ],
      entities: [
        {
          roles: ['registrar'],
          vcardArray: [
            'vcard',
            [
              ['version', {}, 'text', '4.0'],
              ['fn', {}, 'text', 'Cloudflare, Inc.'],
            ],
          ],
          entities: [
            {
              roles: ['abuse'],
              vcardArray: [
                'vcard',
                [
                  ['version', {}, 'text', '4.0'],
                  ['email', {}, 'text', 'abuse@cloudflare.com'],
                ],
              ],
            },
          ],
        },
      ],
      links: [
        {
          rel: 'related',
          href: 'https://cloudflare.com/abuse-form',
        },
      ],
    };

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(sampleRdap), {
        status: 200,
        headers: { 'content-type': 'application/rdap+json' },
      }),
    );

    const hostMap = await lookupHosts(['targethost.org']);
    const record = hostMap.get('targethost.org');

    expect(record).toBeDefined();
    expect(record?.domain).toBe('targethost.org');
    expect(record?.registrar).toBe('Cloudflare, Inc.');
    expect(record?.createdAt).toBe('2019-03-14T12:00:00Z');
    expect(record?.abuseEmail).toBe('abuse@cloudflare.com');
    expect(record?.abuseFormUrl).toBe('https://cloudflare.com/abuse-form');
    expect(record?.ip).toBe('198.51.100.22');
    expect(record?.hostingProvider).toContain('CDN: Cloudflare');
    expect(record?.sources).toContain('https://rdap.org/domain/targethost.org');
    expect(record?.sources).toContain('dns:resolve4');

    expect(() => HostRecordSchema.parse(record)).not.toThrow();
  });

  it('records error message gracefully on RDAP 404 or network failure', async () => {
    vi.spyOn(dns, 'resolve4').mockRejectedValue(new Error('NXDOMAIN'));
    global.fetch = vi.fn().mockResolvedValue(
      new Response('Not Found', { status: 404 }),
    );

    const hostMap = await lookupHosts(['nonexistent-domain.org']);
    const record = hostMap.get('nonexistent-domain.org');

    expect(record).toBeDefined();
    expect(record?.error).toContain('HTTP 404');
    expect(() => HostRecordSchema.parse(record)).not.toThrow();
  });
});

describe('Image Verification Thresholds', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('USE_MOCKS', 'false');
    vi.stubEnv('TINYFISH_API_KEY', 'test-key');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('verifies candidates according to 0.90 verified and 0.75 possible thresholds', async () => {
    // Generate original image
    const originalImage = await sharp({
      create: { width: 32, height: 32, channels: 3, background: '#123456' },
    })
      .png()
      .toBuffer();

    // Exact identical candidate (similarity 1.0)
    const identicalCandidateImage = Buffer.from(originalImage);

    // Slightly modified image (similarity around 0.8)
    const slightModCandidateImage = await sharp({
      create: { width: 32, height: 32, channels: 3, background: '#123477' },
    })
      .png()
      .toBuffer();

    // Completely different image (similarity low)
    const differentImage = await sharp({
      create: {
        width: 32,
        height: 32,
        channels: 3,
        background: { r: 255, g: 255, b: 255 },
      },
    })
      .png()
      .toBuffer();

    vi.spyOn(dns, 'lookup').mockImplementation(async () => [
      { address: '93.184.216.34', family: 4 },
    ] as never);

    global.fetch = vi.fn().mockImplementation((url: string) => {
      let buf = differentImage;
      if (url.includes('identical')) buf = identicalCandidateImage;
      else if (url.includes('slight')) buf = slightModCandidateImage;

      return Promise.resolve(
        new Response(buf, {
          status: 200,
          headers: { 'content-type': 'image/png' },
        }),
      );
    });

    const candidates = [
      {
        url: 'https://example.com/p1',
        platform: 'web' as const,
        verification: 'unverified' as const,
        source: 'search' as const,
        matchedImageUrl: 'https://example.com/identical.png',
      },
      {
        url: 'https://example.com/p2',
        platform: 'web' as const,
        verification: 'unverified' as const,
        source: 'search' as const,
        matchedImageUrl: 'https://example.com/slight.png',
      },
      {
        url: 'https://example.com/p3',
        platform: 'web' as const,
        verification: 'unverified' as const,
        source: 'search' as const,
        matchedImageUrl: 'https://example.com/different.png',
      },
    ];

    const verified = await verifyCandidates(candidates, originalImage);

    // Candidate 1 (identical) must be 'verified' (>= 0.90)
    expect(verified[0]?.similarity).toBeGreaterThanOrEqual(VERIFIED_MIN_SIMILARITY);
    expect(verified[0]?.verification).toBe('verified');

    // Candidate 2 has similarity calculated
    expect(typeof verified[1]?.similarity).toBe('number');
    if (verified[1]!.similarity! >= VERIFIED_MIN_SIMILARITY) {
      expect(verified[1]?.verification).toBe('verified');
    } else if (verified[1]!.similarity! >= POSSIBLE_MIN_SIMILARITY) {
      expect(verified[1]?.verification).toBe('possible');
    }

    // Candidate 3 verification matches its similarity
    if (verified[2]!.similarity! < POSSIBLE_MIN_SIMILARITY) {
      expect(verified[2]?.verification).toBe('unverified');
    }
  });

  it('keeps candidate unverified when originalImageBuffer is omitted', async () => {
    const candidates = [
      {
        url: 'https://example.com/p1',
        platform: 'web' as const,
        verification: 'unverified' as const,
        source: 'search' as const,
      },
    ];

    const results = await verifyCandidates(candidates);
    expect(results[0]?.verification).toBe('unverified');
  });
});

describe('Mock Mode (isMock: true, *.example domains)', () => {
  beforeEach(() => {
    vi.stubEnv('USE_MOCKS', 'true');
    vi.stubEnv('TINYFISH_API_KEY', '');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('detects mock mode when USE_MOCKS is true', () => {
    expect(isMockMode()).toBe(true);
  });

  it('detects mock mode when TINYFISH_API_KEY is missing', () => {
    vi.stubEnv('USE_MOCKS', 'false');
    vi.stubEnv('TINYFISH_API_KEY', '');
    expect(isMockMode()).toBe(true);
  });

  it('returns realistic fake candidates on *.example domains in mock mode', async () => {
    const candidates = await searchCandidates(['victim photo leak search']);

    expect(candidates.length).toBeGreaterThan(0);
    for (const c of candidates) {
      expect(c.url).toMatch(/\.example/);
      expect(c.verification).toBe('unverified');
      expect(c.source).toBe('search');
      expect(() => CandidateMatchSchema.parse(c)).not.toThrow();
    }
  });

  it('enriches mock candidates with metadata and image URLs on *.example', async () => {
    const initialCandidates = await searchCandidates(['victim photo leak']);
    const enriched = await enrichCandidates(initialCandidates);

    expect(enriched.length).toBeGreaterThan(0);
    for (const e of enriched) {
      expect(e.source).toBe('fetch');
      expect(e.title).toBeDefined();
      expect(e.matchedImageUrl).toMatch(/\.example/);
      expect(() => CandidateMatchSchema.parse(e)).not.toThrow();
    }
  });

  it('provides realistic host records for *.example domains in mock mode', async () => {
    const hosts = await lookupHosts(['mirror-1.example', 'reddit.example']);

    expect(hosts.size).toBe(2);
    const mirror = hosts.get('mirror-1.example');
    expect(mirror).toBeDefined();
    expect(mirror?.domain).toBe('mirror-1.example');
    expect(mirror?.registrar).toBe('Example Registrar LLC');
    expect(mirror?.abuseEmail).toBe('abuse@mirror-1.example');
    expect(() => HostRecordSchema.parse(mirror)).not.toThrow();
  });

  it('full runTinyFishSearch orchestrates and returns valid OsintResult in mock mode', async () => {
    const originalBuf = await sharp({
      create: { width: 20, height: 20, channels: 3, background: 'blue' },
    })
      .png()
      .toBuffer();

    const results = await runTinyFishSearch(['blue jacket park bench'], {
      originalImageBuffer: originalBuf,
    });

    expect(results).toHaveLength(1);
    const osint = results[0]!;
    expect(osint.isMock).toBe(true);
    expect(osint.query).toBe('blue jacket park bench');
    expect(osint.candidates.length).toBeGreaterThan(0);
    expect(osint.hosts.length).toBeGreaterThan(0);
    expect(osint.errors).toEqual([]);

    expect(() => OsintResultSchema.parse(osint)).not.toThrow();
  });
});
