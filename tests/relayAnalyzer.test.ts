import { describe, it, expect } from 'vitest';
import { parseRawEmail } from '../server/emailParser';
import { analyzeRelayHops } from '../server/relayAnalyzer';

describe('Relay Analyzer & Origin Node Reconstruction', () => {
  it('should parse multi-hop received chain in correct chronological order', () => {
    const rawEml = `Received: from mail.corporate-gateway.internal (10.0.4.15) by mx1.company.com with ESMTP id 98124; Wed, 26 Aug 2026 09:14:22 +0000
Received: from tor-relay-frankfurt.zwiebelfreunde.de ([185.220.101.5]) by mail.corporate-gateway.internal with ESMTPS id 55431 for <cfo@acme.com>; Wed, 26 Aug 2026 09:14:18 +0000
Received: from desktop-agent-x9.lan (192.168.1.104) by tor-relay-frankfurt.zwiebelfreunde.de with ESMTPA id 11029; Wed, 26 Aug 2026 09:14:10 +0000
From: ceo@acme.com
To: cfo@acme.com
Subject: Test

Message body`;

    const parsed = parseRawEmail(rawEml);
    const relay = analyzeRelayHops(parsed);

    expect(relay.relay_hops.length).toBeGreaterThanOrEqual(2);
    expect(relay.origin_candidates.length).toBeGreaterThanOrEqual(1);

    // Origin candidate should identify the external IP
    const firstOrigin = relay.origin_candidates[0];
    expect(firstOrigin.ip_address).toBe('185.220.101.5');
  });

  it('should flag private RFC 1918 hops accurately', () => {
    const rawEml = `Received: from internal-node.lan (10.0.1.5) by gateway.lan (192.168.1.1); Wed, 26 Aug 2026 09:14:10 +0000
From: a@b.com
To: c@d.com
Subject: Internal

Internal msg`;

    const parsed = parseRawEmail(rawEml);
    const relay = analyzeRelayHops(parsed);

    for (const hop of relay.relay_hops) {
      if (hop.ip_address.startsWith('10.') || hop.ip_address.startsWith('192.168.')) {
        expect(hop.is_private).toBe(true);
      }
    }
  });
});
