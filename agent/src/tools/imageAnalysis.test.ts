import { Buffer } from 'node:buffer';
import sharp from 'sharp';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ImageAnalysisResultSchema } from '../types.js';
import {
  AnalysisError,
  ImageValidationError,
  analyzeAndGenerateQueries,
  computePerceptualHash,
  detectImageType,
  hashSimilarity,
  prepareForModel,
  sha256Hex,
  wipeBuffer,
} from './imageAnalysis.js';

const { generate } = vi.hoisted(() => ({
  generate: vi.fn<(...args: unknown[]) => Promise<{ text: string }>>(),
}));
vi.mock('ai', () => ({ generateText: generate }));

const queries = ['blue jacket garden pathway', 'red umbrella brick pavement', 'wooden bench leafy background'];

/** Build a complete provider response without any external requests. */
function response(overrides: Record<string, unknown> = {}): { text: string } {
  return {
    text: JSON.stringify({
      possibleMinor: false,
      sceneSummary: 'A neutral garden scene.',
      searchQueries: queries,
      ...overrides,
    }),
  };
}

let image: Buffer;

beforeAll(async () => {
  image = await sharp({ create: { width: 40, height: 20, channels: 3, background: '#637ac9' } })
    .png().toBuffer();
});

beforeEach(() => {
  generate.mockReset();
  vi.stubEnv('USE_MOCKS', 'false');
  vi.stubEnv('OPENAI_API_KEY', 'test-key');
  vi.stubEnv('VISION_MODEL', '');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('image helpers', () => {
  it('detects real JPEG, PNG, and WebP buffers', async () => {
    expect(detectImageType(image)).toBe('image/png');
    expect(detectImageType(await sharp(image).jpeg().toBuffer())).toBe('image/jpeg');
    expect(detectImageType(await sharp(image).webp().toBuffer())).toBe('image/webp');
  });

  it.each([
    Buffer.alloc(0), Buffer.from('GIF89a'), Buffer.from([0xff, 0xd8]),
    Buffer.from('89504e470d0a1a', 'hex'), Buffer.from('RIFF0000WAVE'),
    Buffer.from('d2c9c6c630303030d7c5c2d0', 'hex'),
  ])('rejects incomplete or unsupported magic bytes (%j)', (input: Buffer) => {
    expect(detectImageType(input)).toBeNull();
  });

  it('hashes the original bytes with SHA-256 without mutating them', () => {
    const original = Buffer.from('abc');
    expect(sha256Hex(original)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(original.toString()).toBe('abc');
    expect(sha256Hex(Buffer.alloc(0))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('prepares bounded JPEGs, strips metadata, and leaves the original untouched', async () => {
    const source = await sharp({ create: { width: 2048, height: 512, channels: 3, background: 'blue' } })
      .withMetadata({ exif: { IFD0: { Artist: 'Private author' } } }).png().toBuffer();
    const original = Buffer.from(source);
    const prepared = await prepareForModel(source);
    const metadata = await sharp(prepared).metadata();
    expect(metadata).toMatchObject({ format: 'jpeg', width: 1024, height: 256 });
    expect(metadata.exif).toBeUndefined();
    expect(metadata.icc).toBeUndefined();
    expect(source).toEqual(original);
    expect(prepared).not.toBe(source);
  });

  it('applies EXIF orientation without enlarging small images', async () => {
    const oriented = await sharp(image).jpeg().withMetadata({ orientation: 6 }).toBuffer();
    expect(await sharp(await prepareForModel(oriented)).metadata())
      .toMatchObject({ width: 20, height: 40 });
  });

  it('rejects unsupported, oversized, and signature-only undecodable input', async () => {
    for (const input of [Buffer.from('bad'), Buffer.alloc(10 * 1024 * 1024 + 1), image.subarray(0, 8)]) {
      await expect(prepareForModel(input)).rejects.toBeInstanceOf(ImageValidationError);
      await expect(computePerceptualHash(input)).rejects.toBeInstanceOf(ImageValidationError);
    }
  });

  it('accepts the exact 10 MiB boundary', async () => {
    const padded = Buffer.alloc(10 * 1024 * 1024);
    image.copy(padded);
    expect(detectImageType(await prepareForModel(padded))).toBe('image/jpeg');
  });

  it('computes the expected 64 row-major comparisons and preserves leading zeros', async () => {
    for (const descending of [false, true]) {
      const pixels = Buffer.from(Array.from({ length: 72 }, (_, index) =>
        descending ? 240 - (index % 9) * 25 : (index % 9) * 25));
      const gradient = await sharp(pixels, { raw: { width: 9, height: 8, channels: 1 } }).png().toBuffer();
      expect(await computePerceptualHash(gradient)).toBe(descending ? 'ffffffffffffffff' : '0000000000000000');
    }
    expect(await computePerceptualHash(image)).toBe('0000000000000000');
  });

  it('uses image orientation in perceptual hashing', async () => {
    const pixels = Buffer.from(Array.from({ length: 24 * 16 * 3 }, (_, index) => (index * 31) % 256));
    const oriented = await sharp(pixels, { raw: { width: 24, height: 16, channels: 3 } })
      .jpeg().withMetadata({ orientation: 6 }).toBuffer();
    const rotated = await sharp(oriented).rotate().png().toBuffer();
    expect(await computePerceptualHash(oriented)).toBe(await computePerceptualHash(rotated));
  });

  it('calculates normalized Hamming distance, including upper-case hashes', () => {
    expect(hashSimilarity('0000000000000000', '0000000000000000')).toBe(1);
    expect(hashSimilarity('ffffffffffffffff', '0000000000000000')).toBe(0);
    expect(hashSimilarity('0000000000000001', '0000000000000000')).toBe(63 / 64);
    expect(hashSimilarity('FFFFFFFFFFFFFFFF', 'ffffffffffffffff')).toBe(1);
    expect(hashSimilarity('00000000ffffffff', '0000000000000000')).toBe(0.5);
  });

  it.each(['', '0000', 'g000000000000000', '00000000000000000', ' 000000000000000'])
    ('validates both perceptual hashes: %s', (invalid: string) => {
      expect(() => hashSimilarity(invalid, '0000000000000000')).toThrow(ImageValidationError);
      expect(() => hashSimilarity('0000000000000000', invalid)).toThrow(ImageValidationError);
    });

  it('overwrites all bytes, including views, and handles an empty buffer', () => {
    const original = Buffer.from([1, 2, 3, 4]);
    wipeBuffer(original.subarray(1, 3));
    expect(original).toEqual(Buffer.from([1, 0, 0, 4]));
    wipeBuffer(original);
    expect(original).toEqual(Buffer.alloc(4));
    expect(() => wipeBuffer(Buffer.alloc(0))).not.toThrow();
  });
});

describe('vision and safety', () => {
  it('uses SDK 6 image parts, optional context, and returns validated metadata', async () => {
    generate.mockResolvedValue(response());
    vi.stubEnv('VISION_MODEL', 'custom-vision');
    const original = Buffer.from(image);
    const result = await analyzeAndGenerateQueries(image, { userContext: 'A garden background' });
    expect(ImageAnalysisResultSchema.safeParse(result).success).toBe(true);
    expect(result).toMatchObject({
      imageHash: sha256Hex(image), searchQueries: queries, model: 'custom-vision',
      safety: { possibleMinor: false, blocked: false }, isMock: false,
    });
    expect(result).not.toHaveProperty('sceneSummary');
    expect(image).toEqual(original);
    expect(generate).toHaveBeenCalledOnce();
    expect(generate).toHaveBeenCalledWith(expect.objectContaining({
      maxRetries: 0,
      experimental_telemetry: { isEnabled: false },
      messages: [{ role: 'user', content: [
        { type: 'image', image: expect.any(Buffer), mediaType: 'image/jpeg' },
        { type: 'text', text: expect.stringContaining('A garden background') },
      ] }],
    }));
  });

  it('uses the default model and wipes the prepared buffer after success', async () => {
    generate.mockResolvedValue(response());
    expect((await analyzeAndGenerateQueries(image)).model).toBe('gpt-4o-mini');
    expectPreparedWiped();
  });

  it('trims, normalizes whitespace, deduplicates, and drops emails and handles', async () => {
    generate.mockResolvedValue(response({ searchQueries: [
      '  blue   jacket garden pathway  ', ...queries.slice(1), 'owner@example.com outdoor garden', '@person outdoor garden',
    ] }));
    expect((await analyzeAndGenerateQueries(image)).searchQueries).toEqual(queries);
    generate.mockReset().mockResolvedValue(response({ searchQueries: [...queries, queries[0]!.toUpperCase()] }));
    expect((await analyzeAndGenerateQueries(image)).searchQueries).toEqual(queries);
  });

  it('caps excess safe queries at five after filtering', async () => {
    const extras = ['gray stone garden walkway', 'green leaves cloudy sky', 'orange flowers white fence'];
    generate.mockResolvedValue(response({ searchQueries: [...queries, ...extras] }));
    expect((await analyzeAndGenerateQueries(image)).searchQueries).toEqual([...queries, ...extras.slice(0, 2)]);
    expect(generate).toHaveBeenCalledOnce();
  });

  it.each([
    { text: 'not JSON' },
    { text: '```json\n{}\n```' },
    response({ possibleMinor: 'false' }),
    response({ sceneSummary: null }),
    response({ searchQueries: [queries[0], queries[0], queries[0]] }),
    response({ searchQueries: ['too short', 'one two three four five six seven eight nine ten eleven twelve thirteen', queries[0]] }),
    response({ searchQueries: ['@person garden background', 'owner@example.com garden background', queries[0]] }),
  ])('retries invalid structured output once and recovers (%j)', async (invalid: { text: string }) => {
    generate.mockResolvedValueOnce(invalid).mockResolvedValueOnce(response());
    expect((await analyzeAndGenerateQueries(image)).searchQueries).toEqual(queries);
    expect(generate).toHaveBeenCalledTimes(2);
    expectPreparedWiped();
  });

  it.each([{ text: 'invalid' }, response({ searchQueries: [] }), response({ possibleMinor: null })])
    ('throws a typed, sanitized error after two invalid outputs (%j)', async (invalid: { text: string }) => {
      generate.mockResolvedValue(invalid);
      await expect(analyzeAndGenerateQueries(image)).rejects.toMatchObject({ name: 'AnalysisError', code: 'INVALID_RESPONSE' });
      expect(generate).toHaveBeenCalledTimes(2);
      expectPreparedWiped();
    });

  it.each([{ minorQueries: [] }, { minorQueries: queries }])('blocks possible minors and returns no queries (%j)', async ({ minorQueries }: { minorQueries: string[] }) => {
    generate.mockResolvedValue(response({ possibleMinor: true, searchQueries: minorQueries }));
    const result = await analyzeAndGenerateQueries(image);
    expect(result.searchQueries).toEqual([]);
    expect(result.safety).toMatchObject({ possibleMinor: true, blocked: true, reason: expect.any(String) });
    expect(generate).toHaveBeenCalledOnce();
    expectPreparedWiped();
  });

  it('preserves a positive minor signal even if the descriptive fields are invalid', async () => {
    generate.mockResolvedValueOnce(response({ possibleMinor: true, sceneSummary: null, searchQueries: null }))
      .mockResolvedValueOnce(response());
    expect(await analyzeAndGenerateQueries(image)).toMatchObject({
      searchQueries: [], safety: { possibleMinor: true, blocked: true }, isMock: false,
    });
    expect(generate).toHaveBeenCalledOnce();
    expectPreparedWiped();
  });

  it.each([429, 500, 503, 599])('retries a %i provider error exactly once', async (statusCode: number) => {
    generate.mockRejectedValueOnce({ statusCode, requestBody: 'private' }).mockResolvedValueOnce(response());
    expect((await analyzeAndGenerateQueries(image)).isMock).toBe(false);
    expect(generate).toHaveBeenCalledTimes(2);
    expectPreparedWiped();
  });

  it.each([400, 401, 403, 404, 600, undefined])('does not retry nontransient provider errors (%s)', async (statusCode: number | undefined) => {
    generate.mockRejectedValue({ statusCode, message: 'private image request' });
    await expect(analyzeAndGenerateQueries(image)).rejects.toMatchObject({ name: 'AnalysisError', code: 'PROVIDER_ERROR', statusCode });
    expect(generate).toHaveBeenCalledOnce();
    expectPreparedWiped();
  });

  it('does not expose provider request bodies in error causes or messages', async () => {
    generate.mockRejectedValue({ statusCode: 503, requestBody: 'PRIVATE_BYTES' });
    await expect(analyzeAndGenerateQueries(image)).rejects.toEqual(new AnalysisError('Vision provider request failed.', 'PROVIDER_ERROR', 503));
    expect(generate).toHaveBeenCalledTimes(2);
    expectPreparedWiped();
  });

  it('shares the one provider retry budget across validation attempts', async () => {
    generate.mockRejectedValueOnce({ statusCode: 429 })
      .mockResolvedValueOnce({ text: 'invalid' })
      .mockRejectedValueOnce({ statusCode: 503 });
    await expect(analyzeAndGenerateQueries(image)).rejects.toBeInstanceOf(AnalysisError);
    expect(generate).toHaveBeenCalledTimes(3);
    expectPreparedWiped();
  });

  it.each(['enabled', 'missing key', 'blank key'])('returns four deterministic, explicitly mocked queries: %s', async (mode: string) => {
    if (mode === 'enabled') vi.stubEnv('USE_MOCKS', 'true');
    else vi.stubEnv('OPENAI_API_KEY', mode === 'blank key' ? '  ' : undefined);
    const first = await analyzeAndGenerateQueries(image);
    const second = await analyzeAndGenerateQueries(image);
    expect(first.searchQueries).toEqual(second.searchQueries);
    expect(first.searchQueries).toHaveLength(4);
    expect(new Set(first.searchQueries).size).toBe(4);
    expect(first.searchQueries[0]).toContain(sha256Hex(image).slice(0, 8));
    expect(first).toMatchObject({ isMock: true, safety: { possibleMinor: false, blocked: false } });
    expect(ImageAnalysisResultSchema.safeParse(first).success).toBe(true);
    const different = await sharp(image).flop().jpeg().toBuffer();
    expect((await analyzeAndGenerateQueries(different)).searchQueries).not.toEqual(first.searchQueries);
    expect(generate).not.toHaveBeenCalled();
  });

  it('validates type, size, and decodability even in mock mode', async () => {
    vi.stubEnv('USE_MOCKS', 'true');
    for (const input of [Buffer.from('bad'), Buffer.alloc(10 * 1024 * 1024 + 1), image.subarray(0, 8)]) {
      await expect(analyzeAndGenerateQueries(input)).rejects.toBeInstanceOf(ImageValidationError);
    }
    expect(generate).not.toHaveBeenCalled();
  });

  it('rejects invalid user context before any provider request', async () => {
    await expect(analyzeAndGenerateQueries(image, { userContext: 'a'.repeat(301) }))
      .rejects.toMatchObject({ code: 'INVALID_CONTEXT' });
    expect(generate).not.toHaveBeenCalled();
  });
});

/** Verify the actual buffer passed to the provider was cleared on every request. */
function expectPreparedWiped(): void {
  for (const call of generate.mock.calls) {
    const request = call[0] as { messages: [{ content: [{ image: Buffer }] }] };
    const prepared = request.messages[0].content[0].image;
    expect(prepared.length).toBeGreaterThan(0);
    expect(prepared.every((byte: number) => byte === 0)).toBe(true);
  }
}
