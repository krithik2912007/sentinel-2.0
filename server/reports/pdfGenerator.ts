import PDFDocument from 'pdfkit';
import { AnalyzedEmail, CaseRecord } from '../../src/types';

export function generateForensicPdf(email: AnalyzedEmail, caseRecord?: CaseRecord | null): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 40, size: 'A4' });
      const buffers: Buffer[] = [];

      doc.on('data', (chunk) => buffers.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(buffers)));

      // Colors
      const primary = '#0f172a'; // Slate 900
      const accent = email.risk_score >= 75 ? '#dc2626' : email.risk_score >= 45 ? '#ea580c' : '#16a34a';
      const textMuted = '#475569';
      const textDark = '#1e293b';

      // Header
      doc.rect(40, 40, 515, 60).fill('#020617');
      doc.fillColor('#ffffff').fontSize(16).font('Helvetica-Bold').text('SENTINEL AI — FORENSIC THREAT INTELLIGENCE DOSSIER', 55, 52);
      doc.fontSize(9).font('Helvetica').fillColor('#94a3b8').text(`CLASSIFICATION: ${email.classification} | RISK SCORE: ${email.risk_score}/100 | EVIDENCE SHA-256: ${email.evidence_hash.substring(0, 16)}...`, 55, 75);

      doc.moveDown(3);

      // Metadata Grid
      const startY = 115;
      doc.fillColor(primary).fontSize(12).font('Helvetica-Bold').text('1. EXECUTIVE SUMMARY & THREAT ASSESSMENT', 40, startY);
      doc.moveDown(0.4);

      doc.rect(40, doc.y, 515, 80).fillAndStroke('#f8fafc', '#e2e8f0');
      const boxY = doc.y + 10;
      doc.fillColor(textDark).fontSize(9).font('Helvetica-Bold').text('Risk Score:', 50, boxY);
      doc.fillColor(accent).font('Helvetica-Bold').text(`${email.risk_score} / 100 (${email.classification})`, 120, boxY);

      doc.fillColor(textDark).font('Helvetica-Bold').text('Confidence:', 320, boxY);
      doc.fillColor(textMuted).font('Helvetica').text(`${Math.round(email.confidence * 100)}%`, 390, boxY);

      doc.fillColor(textDark).font('Helvetica-Bold').text('Subject:', 50, boxY + 16);
      doc.fillColor(textDark).font('Helvetica').text(email.subject || '(No Subject)', 120, boxY + 16, { width: 420 });

      doc.fillColor(textDark).font('Helvetica-Bold').text('Sender:', 50, boxY + 32);
      doc.fillColor(textDark).font('Helvetica').text(`${email.sender_name || ''} <${email.sender_email || ''}>`, 120, boxY + 32);

      doc.fillColor(textDark).font('Helvetica-Bold').text('Case Dossier:', 50, boxY + 48);
      doc.fillColor(textDark).font('Helvetica').text(caseRecord ? `${caseRecord.case_number} — ${caseRecord.title}` : 'Unassigned', 120, boxY + 48);

      doc.y = boxY + 75;
      doc.moveDown(0.8);

      // Executive Summary Text
      doc.fillColor(textDark).fontSize(9).font('Helvetica').text(email.executive_summary || 'No executive summary provided.', {
        align: 'justify',
        width: 515,
      });

      doc.moveDown(1.2);

      // 2. Cryptographic Evidence Hashes
      doc.fillColor(primary).fontSize(11).font('Helvetica-Bold').text('2. FORENSIC CHAIN OF CUSTODY & EVIDENCE HASHES');
      doc.moveDown(0.3);

      doc.fontSize(8).font('Courier').fillColor(textDark);
      doc.text(`SHA-256 : ${email.evidence_hash}`);
      doc.text(`SHA-1   : ${email.sha1_hash}`);
      doc.text(`MD5     : ${email.md5_hash}`);
      doc.text(`Ingested: ${email.ingested_at}`);

      doc.moveDown(1.2);

      // 3. Email Authentication
      doc.fillColor(primary).fontSize(11).font('Helvetica-Bold').text('3. EMAIL AUTHENTICATION & IDENTITY VERIFICATION');
      doc.moveDown(0.3);

      doc.fontSize(9).font('Helvetica');
      doc.fillColor(textDark).text(`• SPF:   ${email.auth_analysis.spf.result.toUpperCase()} — ${email.auth_analysis.spf.explanation}`);
      doc.fillColor(textDark).text(`• DKIM:  ${email.auth_analysis.dkim.result.toUpperCase()} (Signature Present: ${email.auth_analysis.dkim.signature_present ? 'YES' : 'NO'}, Domain: ${email.auth_analysis.dkim.signing_domain || 'None'})`);
      doc.fillColor(textDark).text(`• DMARC: ${email.auth_analysis.dmarc.result.toUpperCase()} (Policy: ${(email.auth_analysis.dmarc.policy || 'none').toUpperCase()}, Alignment: ${email.auth_analysis.dmarc.spf_aligned && email.auth_analysis.dmarc.dkim_aligned ? 'ALIGNED' : 'FAIL'})`);


      doc.moveDown(1.2);

      // 4. Suspected Origin Infrastructure
      doc.fillColor(primary).fontSize(11).font('Helvetica-Bold').text('4. SUSPECTED ORIGIN INFRASTRUCTURE');
      doc.moveDown(0.3);

      if (email.origin_candidates && email.origin_candidates.length > 0) {
        for (const origin of email.origin_candidates.slice(0, 3)) {
          doc.fontSize(8.5).font('Helvetica-Bold').fillColor(textDark).text(`Hop #${origin.hop_number} — IP: ${origin.ip_address} (Reliability Score: ${origin.reliability_score}%)`);
          doc.font('Helvetica').fillColor(textMuted).text(`Infrastructure: ${origin.infrastructure_info} | Geo: ${origin.geo?.city || 'N/A'}, ${origin.geo?.country || 'N/A'} (ASN: ${origin.geo?.asn || 'N/A'})`);
          doc.text(`Limitations: ${origin.limitations}`);
          doc.moveDown(0.4);
        }
      } else {
        doc.fontSize(8.5).font('Helvetica').fillColor(textMuted).text('No external origin candidate hops identified in received headers.');
      }

      doc.moveDown(0.8);

      // 5. MITRE ATT&CK & Recommendations
      doc.fillColor(primary).fontSize(11).font('Helvetica-Bold').text('5. MITRE ATT&CK MAPPING & DEFENSIVE RECOMMENDATIONS');
      doc.moveDown(0.3);

      if (email.mitre_attack && email.mitre_attack.length > 0) {
        doc.fontSize(8.5).font('Helvetica').fillColor(textDark);
        for (const m of email.mitre_attack) {
          doc.text(`• [${m.technique_id}] ${m.technique_name} (${m.tactic}): ${m.description}`);
        }
      }

      doc.moveDown(0.5);

      if (email.defensive_recommendations && email.defensive_recommendations.length > 0) {
        doc.fontSize(8.5).font('Helvetica-Bold').fillColor(primary).text('Defensive Actions:');
        doc.font('Helvetica').fillColor(textDark);
        for (const rec of email.defensive_recommendations.slice(0, 4)) {
          doc.text(`- ${rec}`);
        }
      }

      doc.moveDown(1.5);

      // Disclaimer Box
      doc.rect(40, doc.y, 515, 45).fillAndStroke('#fef2f2', '#fecaca');
      const discY = doc.y + 6;
      doc.fillColor('#991b1b').fontSize(7.5).font('Helvetica-Bold').text('LEGAL & FORENSIC ATTRIBUTION DISCLAIMER:', 50, discY);
      doc.font('Helvetica').fillColor('#7f1d1d').text(
        'IP geolocation identifies network routing infrastructure associated with an IP address. It does not by itself establish the physical location or legal identity of an attacker. Chain of custody hashes verify evidence integrity at ingestion time.',
        50,
        discY + 12,
        { width: 495 }
      );

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
