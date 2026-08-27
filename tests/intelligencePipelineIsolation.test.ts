import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseRawEmail } from '../server/emailParser';
import { analyzeRelayHops } from '../server/relayAnalyzer';
import { analyzeThreats } from '../server/threatEngine';
import { PRESET_SAMPLES } from '../server/sampleData';
import { virusTotalProvider } from '../server/intelligence/virusTotalProvider';
import { abuseIpdbProvider } from '../server/intelligence/abuseIpdbProvider';

describe('Threat Pipeline Intelligence Isolation & Resilience', () => {
  beforeEach(() => {
    process.env.IN_MEMORY_DEMO_MODE = 'true';
    vi.restoreAllMocks();
  });

  it('completes deterministic analysis safely when all intelligence providers are not configured', async () => {
    delete process.env.VIRUSTOTAL_API_KEY;
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.IPQS_API_KEY;
    delete process.env.WHOIS_API_KEY;
    delete process.env.IPINFO_TOKEN;
    delete process.env.GEMINI_API_KEY;

    const sample = PRESET_SAMPLES.find((s) => s.id === 'sample-bec-ceo') || PRESET_SAMPLES[0];
    const parsed = parseRawEmail(sample.eml);
    const relayResult = analyzeRelayHops(parsed.received_headers);

    const threatResult = await analyzeThreats(parsed, relayResult);

    expect(threatResult).toBeDefined();
    expect(threatResult.risk_score).toBeGreaterThan(0);
    expect(threatResult.classification).toBeDefined();
    expect(threatResult.evidence_list.length).toBeGreaterThan(0);
    expect(threatResult.auth_analysis).toBeDefined();
  });

  it('completes analysis safely when an external provider encounters network errors or timeouts', async () => {
    // Force provider methods to reject/throw
    vi.spyOn(virusTotalProvider, 'lookupHash').mockRejectedValueOnce(new Error('Network connection refused (ECONNREFUSED)'));
    vi.spyOn(abuseIpdbProvider, 'lookupIp').mockRejectedValueOnce(new Error('DNS lookup failure (ENOTFOUND)'));

    const sample = PRESET_SAMPLES.find((s) => s.id === 'sample-credential-harvest') || PRESET_SAMPLES[1];
    const parsed = parseRawEmail(sample.eml);
    const relayResult = analyzeRelayHops(parsed.received_headers);

    const threatResult = await analyzeThreats(parsed, relayResult);

    expect(threatResult).toBeDefined();
    expect(threatResult.classification).toBeDefined();
    expect(threatResult.risk_score).toBeGreaterThan(0);
  });

  it('elevates risk score and adds evidence when VirusTotal reports malicious attachments', async () => {
    const sample = PRESET_SAMPLES.find((s) => s.id === 'sample-invoice-malware') || PRESET_SAMPLES[2];
    const parsed = parseRawEmail(sample.eml);
    const relayResult = analyzeRelayHops(parsed.received_headers);

    const targetHash = parsed.attachments[0]?.sha256 || '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

    vi.spyOn(virusTotalProvider, 'lookupHash').mockResolvedValueOnce({
      provider: 'VirusTotal',
      status: 'LIVE',
      indicator_type: 'HASH',
      indicator: targetHash,
      reputation: 'MALICIOUS',
      confidence: 0.99,
      data: {
        malicious: 58,
        suspicious: 3,
        meaningful_name: 'Trojan.Dropper.Agent',
      },
      fetched_at: new Date().toISOString(),
    });

    const threatResult = await analyzeThreats(parsed, relayResult);

    expect(threatResult.risk_score).toBeGreaterThanOrEqual(80);
    const vtEvidence = threatResult.evidence_list.find(
      (e) => e.rule_id === 'RULE_VT_KNOWN_MALICIOUS_HASH' || e.title.includes('VirusTotal')
    );
    expect(vtEvidence).toBeDefined();
  });
});

