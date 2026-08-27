import { describe, it, expect } from 'vitest';
import { parseRawEmail } from '../server/emailParser';
import { PRESET_SAMPLES } from '../server/sampleData';

describe('Email Parser (RFC 5322 / MIME)', () => {
  it('should parse standard headers, sender, and recipient', () => {
    const rawEml = `From: "Chief Executive" <ceo@acme.com>
To: "Finance" <finance@acme.com>
Subject: Urgent Wire Request
Date: Wed, 26 Aug 2026 10:00:00 +0000
Message-ID: <msg-101@acme.com>
Content-Type: text/plain; charset=UTF-8

Please process the wire immediately.`;

    const parsed = parseRawEmail(rawEml);
    expect(parsed.from_email).toBe('ceo@acme.com');
    expect(parsed.from_name).toBe('Chief Executive');
    expect(parsed.to_email).toBe('finance@acme.com');
    expect(parsed.subject).toBe('Urgent Wire Request');
    expect(parsed.body_plain.trim()).toBe('Please process the wire immediately.');
    expect(parsed.evidence_hash).toHaveLength(64); // SHA-256
    expect(parsed.sha1_hash).toHaveLength(40); // SHA-1
    expect(parsed.md5_hash).toHaveLength(32); // MD5
  });

  it('should parse all preset test samples without throwing', () => {
    for (const sample of PRESET_SAMPLES) {
      const parsed = parseRawEmail(sample.eml);
      expect(parsed.id).toBeDefined();
      expect(parsed.evidence_hash).toHaveLength(64);
      expect(parsed.sender.email).toBeDefined();
    }
  });

  it('should extract URLs, domains, and IPs from message body', () => {
    const rawEml = `From: user@example.com
To: victim@example.com
Subject: Notice

Visit https://micr0soft-portal.xyz/login or contact 194.26.29.112 directly.`;

    const parsed = parseRawEmail(rawEml);
    expect(parsed.extracted_urls).toContain('https://micr0soft-portal.xyz/login');
    expect(parsed.extracted_domains).toContain('micr0soft-portal.xyz');
    expect(parsed.extracted_ips).toContain('194.26.29.112');
  });
});
