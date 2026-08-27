import { describe, it, expect } from 'vitest';
import { generateForensicPdf } from '../server/reports/pdfGenerator';
import { parseRawEmail } from '../server/emailParser';
import { analyzeRelayHops } from '../server/relayAnalyzer';
import { analyzeThreatDeterministic } from '../server/threatEngine';
import { PRESET_SAMPLES } from '../server/sampleData';

describe('Forensic PDF Generator', () => {
  it('should generate a valid PDF buffer for analyzed emails', async () => {
    const sample = PRESET_SAMPLES[0];
    const parsed = parseRawEmail(sample.eml);
    const relay = analyzeRelayHops(parsed);
    const threat = analyzeThreatDeterministic(parsed, relay);

    const emailRecord = {
      ...parsed,
      risk_score: threat.risk_score,
      classification: threat.classification,
      confidence: threat.confidence,
      executive_summary: threat.executive_summary,
      ai_reasoning: threat.ai_reasoning,
      auth_analysis: threat.auth_analysis,
      relay_hops: relay.relay_hops,
      origin_candidates: relay.origin_candidates,
      evidence_list: threat.evidence_list,
      indicators: threat.indicators,
      content_analysis: threat.content_analysis,
      graph_data: {},
      mitre_attack: threat.mitre_attack,
      defensive_recommendations: threat.defensive_recommendations,
      disclaimers: threat.disclaimers,
    };

    const pdfBuffer = await generateForensicPdf(emailRecord as any);
    expect(Buffer.isBuffer(pdfBuffer)).toBe(true);
    expect(pdfBuffer.length).toBeGreaterThan(1000);
    // PDF Magic number %PDF-
    expect(pdfBuffer.toString('utf8', 0, 5)).toBe('%PDF-');
  });
});
