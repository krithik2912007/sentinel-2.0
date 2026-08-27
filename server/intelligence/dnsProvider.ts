import dns from 'dns';
import { DnsIntelligence } from './types';

const dnsPromises = dns.promises;

function withTimeout<T>(promise: Promise<T>, timeoutMs = 3000): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`DNS resolution timed out after ${timeoutMs}ms`)), timeoutMs)
    ),
  ]);
}

export class DnsProvider {
  async lookupDomain(domain: string): Promise<DnsIntelligence> {
    const cleanDomain = domain.toLowerCase().trim();
    const result: DnsIntelligence = {
      domain: cleanDomain,
      a_records: [],
      aaaa_records: [],
      mx_records: [],
      txt_records: [],
      ns_records: [],
      cname_records: [],
      queried_at: new Date().toISOString(),
      status: 'LIVE',
    };

    try {
      // 1. Resolve A records
      try {
        result.a_records = await withTimeout(dnsPromises.resolve4(cleanDomain));
      } catch {}

      // 2. Resolve AAAA records
      try {
        result.aaaa_records = await withTimeout(dnsPromises.resolve6(cleanDomain));
      } catch {}

      // 3. Resolve MX records
      try {
        const mx = await withTimeout(dnsPromises.resolveMx(cleanDomain));
        result.mx_records = mx.map((m) => ({ exchange: m.exchange, priority: m.priority }));
      } catch {}

      // 4. Resolve TXT records (inspect for SPF)
      try {
        const txt = await withTimeout(dnsPromises.resolveTxt(cleanDomain));
        result.txt_records = txt.map((chunks) => chunks.join(''));
        const spf = result.txt_records.find((t) => t.startsWith('v=spf1'));
        if (spf) result.spf_record = spf;
      } catch {}

      // 5. Resolve DMARC (_dmarc.<domain>)
      try {
        const dmarcTxt = await withTimeout(dnsPromises.resolveTxt(`_dmarc.${cleanDomain}`));
        const flat = dmarcTxt.map((chunks) => chunks.join(''));
        const dmarc = flat.find((t) => t.startsWith('v=DMARC1'));
        if (dmarc) result.dmarc_record = dmarc;
      } catch {}

      // 6. Resolve NS records
      try {
        result.ns_records = await withTimeout(dnsPromises.resolveNs(cleanDomain));
      } catch {}

      // 7. Resolve CNAME records
      try {
        result.cname_records = await withTimeout(dnsPromises.resolveCname(cleanDomain));
      } catch {}

      return result;
    } catch (err: any) {
      result.status = 'ERROR';
      result.error = err.message;
      return result;
    }
  }
}

export const dnsProvider = new DnsProvider();
