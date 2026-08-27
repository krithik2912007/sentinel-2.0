import crypto from 'crypto';
import { AttachmentMetadata } from '../src/types';

export interface ParsedRawEmail {
  id: string;
  evidence_hash: string;
  evidence_hash_sha256: string;
  sha1_hash: string;
  md5_hash: string;
  ingested_at: string;
  headers: Record<string, string>;
  raw_headers: Record<string, string>;
  received_headers: string[];
  subject: string;
  from: string;
  from_name: string;
  from_email: string;
  sender: { raw: string; email: string; name: string };
  sender_raw: string;
  sender_email: string;
  sender_name: string;
  to: string;
  to_email: string;
  recipient: { raw: string; email: string };
  recipient_raw: string;
  recipient_email: string;
  reply_to?: string;
  return_path?: string;
  date?: string;
  date_header?: string;
  message_id?: string;
  body_plain: string;
  body_html?: string;
  attachments: AttachmentMetadata[];
  extracted_urls: string[];
  extracted_ips: string[];
  extracted_domains: string[];
  raw_eml_source?: string;
}

function decodeQuotedPrintable(str: string): string {
  return str
    .replace(/=\r?\n/g, '')
    .replace(/=([A-Fa-f0-9]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function decodeBase64Safe(str: string): string {
  try {
    return Buffer.from(str.replace(/\s+/g, ''), 'base64').toString('utf-8');
  } catch {
    return str;
  }
}

export function parseEmailContent(rawEml: string): ParsedRawEmail {
  const normalized = rawEml.replace(/\r\n/g, '\n');

  // Compute Cryptographic Evidence Hashes
  const evidence_hash_sha256 = crypto.createHash('sha256').update(rawEml).digest('hex');
  const sha1_hash = crypto.createHash('sha1').update(rawEml).digest('hex');
  const md5_hash = crypto.createHash('md5').update(rawEml).digest('hex');

  const headers: Record<string, string> = {};
  const received_headers: string[] = [];

  // Split headers and body at first blank line
  const headerEndIndex = normalized.search(/\n\n/);
  const rawHeaderSection = headerEndIndex !== -1 ? normalized.slice(0, headerEndIndex) : normalized;
  const rawBodySection = headerEndIndex !== -1 ? normalized.slice(headerEndIndex + 2) : '';

  // Unfold multi-line headers (RFC 5322 folding whitespace)
  const headerLines: string[] = [];
  const rawLines = rawHeaderSection.split('\n');

  for (const line of rawLines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && headerLines.length > 0) {
      headerLines[headerLines.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      headerLines.push(line);
    }
  }

  for (const hLine of headerLines) {
    const colonIdx = hLine.indexOf(':');
    if (colonIdx > 0) {
      const key = hLine.slice(0, colonIdx).trim().toLowerCase();
      const val = hLine.slice(colonIdx + 1).trim();

      if (key === 'received') {
        received_headers.push(val);
      } else {
        headers[key] = val;
      }
    }
  }

  // Parse From
  const rawFrom = headers['from'] || 'Unknown Sender <unknown@example.com>';
  let from_name = '';
  let from_email = '';
  const fromMatch = rawFrom.match(/^(.*?)\s*<([^>]+)>/) || rawFrom.match(/()([^@\s]+@[^@\s]+)/);
  if (fromMatch) {
    from_name = fromMatch[1].replace(/["']/g, '').trim();
    from_email = fromMatch[2].trim().toLowerCase();
  } else {
    from_email = rawFrom.trim().toLowerCase();
    from_name = from_email.split('@')[0] || 'Unknown';
  }

  // Parse To
  const rawTo = headers['to'] || 'security-team@corp.internal';
  let to_email = '';
  const toMatch = rawTo.match(/<([^>]+)>/) || rawTo.match(/([^\s<]+@[^\s>]+)/);
  to_email = toMatch ? toMatch[1].toLowerCase() : rawTo.toLowerCase();

  // Extract Return-Path and Reply-To
  let return_path: string | undefined = undefined;
  if (headers['return-path']) {
    const rpMatch = headers['return-path'].match(/<([^>]+)>/) || [null, headers['return-path']];
    return_path = rpMatch[1]?.trim().toLowerCase();
  }

  let reply_to: string | undefined = undefined;
  if (headers['reply-to']) {
    const rtMatch = headers['reply-to'].match(/<([^>]+)>/) || [null, headers['reply-to']];
    reply_to = rtMatch[1]?.trim().toLowerCase();
  }

  // Parse Subject, Date, Message-ID
  const subject = headers['subject'] || '(No Subject)';
  const date = headers['date'] || new Date().toUTCString();
  const message_id = headers['message-id'] || `<msg-${Date.now()}@relay.internal>`;

  // Parse Content / MIME Multi-part
  let body_plain = '';
  let body_html: string | undefined = undefined;
  const attachments: AttachmentMetadata[] = [];

  const contentType = headers['content-type'] || 'text/plain';
  const isMultipart = contentType.toLowerCase().includes('multipart');

  if (isMultipart) {
    const boundaryMatch = contentType.match(/boundary=["']?([^"';\s]+)["']?/i);
    const boundary = boundaryMatch ? boundaryMatch[1] : null;

    if (boundary) {
      const parts = rawBodySection.split(new RegExp(`--${boundary}(?:--)?`));
      for (const part of parts) {
        const trimmedPart = part.trim();
        if (!trimmedPart) continue;

        const partHeaderEnd = trimmedPart.search(/\n\n/);
        const partHeaders = partHeaderEnd !== -1 ? trimmedPart.slice(0, partHeaderEnd) : '';
        let partBody = partHeaderEnd !== -1 ? trimmedPart.slice(partHeaderEnd + 2) : trimmedPart;

        const partHeaderLower = partHeaders.toLowerCase();
        const isHtml = partHeaderLower.includes('text/html');
        const isPlain = partHeaderLower.includes('text/plain');
        const isBase64 = partHeaderLower.includes('content-transfer-encoding: base64');
        const isQP = partHeaderLower.includes('content-transfer-encoding: quoted-printable');

        // Check if attachment
        const dispositionMatch = partHeaders.match(/content-disposition:\s*attachment(?:;\s*filename=["']?([^"';\r\n]+)["']?)?/i);
        const filenameMatch = partHeaders.match(/filename=["']?([^"';\r\n]+)["']?/i) || partHeaders.match(/name=["']?([^"';\r\n]+)["']?/i);

        if (dispositionMatch || filenameMatch || partHeaderLower.includes('application/')) {
          const filename = (filenameMatch ? filenameMatch[1] : (dispositionMatch ? dispositionMatch[1] : 'attachment.dat')) || 'attachment.dat';
          const ext = filename.split('.').pop()?.toLowerCase() || '';
          const isExec = ['exe', 'scr', 'iso', 'bat', 'cmd', 'vbs', 'ps1', 'hta', 'js', 'jar', 'dll', 'docm', 'xlsm'].includes(ext);
          
          const attHash = crypto.createHash('sha256').update(partBody).digest('hex');
          const attMd5 = crypto.createHash('md5').update(partBody).digest('hex');

          attachments.push({
            id: `att-${Date.now()}-${attachments.length + 1}`,
            filename,
            content_type: partHeaders.match(/content-type:\s*([^;\r\n]+)/i)?.[1]?.trim() || 'application/octet-stream',
            size_bytes: Buffer.byteLength(partBody, 'utf8'),
            sha256: attHash,
            md5: attMd5,
            is_executable_or_script: isExec,
            risk_flag: isExec || ext === 'iso' || ext === 'hta',
            detected_threat: isExec ? `Suspicious executable/script file extension (.${ext})` : undefined,
          });
        } else if (isHtml) {
          let decodedHtml = partBody;
          if (isBase64) decodedHtml = decodeBase64Safe(partBody);
          else if (isQP) decodedHtml = decodeQuotedPrintable(partBody);
          body_html = decodedHtml;
          if (!body_plain) {
            body_plain = decodedHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          }
        } else if (isPlain) {
          let decodedPlain = partBody;
          if (isBase64) decodedPlain = decodeBase64Safe(partBody);
          else if (isQP) decodedPlain = decodeQuotedPrintable(partBody);
          body_plain = decodedPlain;
        }
      }
    }
  }

  if (!body_plain && !body_html) {
    // Non-multipart simple email
    let decoded = rawBodySection;
    if (headers['content-transfer-encoding']?.toLowerCase().includes('quoted-printable')) {
      decoded = decodeQuotedPrintable(rawBodySection);
    } else if (headers['content-transfer-encoding']?.toLowerCase().includes('base64')) {
      decoded = decodeBase64Safe(rawBodySection);
    }
    body_plain = decoded;
  }

  // Extract URLs from body & HTML
  const urlRegex = /(https?:\/\/[^\s<>"'\)]+)/gi;
  const combinedText = `${body_plain} ${body_html || ''} ${subject}`;
  const rawUrls = Array.from(combinedText.matchAll(urlRegex), (m) => m[0]);
  const extracted_urls = Array.from(new Set(rawUrls.map((u) => u.replace(/[.,;]$/, ''))));

  // Extract IP addresses (v4)
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const allIpMatches = Array.from(`${rawHeaderSection} ${body_plain}`.matchAll(ipRegex), (m) => m[0]);
  const extracted_ips = Array.from(new Set(allIpMatches));

  // Extract domains
  const extracted_domains = new Set<string>();
  if (from_email && from_email.includes('@')) {
    extracted_domains.add(from_email.split('@')[1]);
  }
  if (return_path && return_path.includes('@')) {
    extracted_domains.add(return_path.split('@')[1]);
  }
  if (reply_to && reply_to.includes('@')) {
    extracted_domains.add(reply_to.split('@')[1]);
  }
  for (const url of extracted_urls) {
    try {
      const parsedUrl = new URL(url);
      extracted_domains.add(parsedUrl.hostname.toLowerCase());
    } catch {
      // ignore invalid
    }
  }

  const emailId = `eml_${evidence_hash_sha256.slice(0, 16)}`;
  const nowIso = new Date().toISOString();

  return {
    id: emailId,
    evidence_hash: evidence_hash_sha256,
    evidence_hash_sha256,
    sha1_hash,
    md5_hash,
    ingested_at: nowIso,
    headers,
    raw_headers: headers,
    received_headers,
    subject: subject || '(No Subject)',
    from: rawFrom,
    from_name: from_name || 'Sender',
    from_email,
    sender: {
      raw: rawFrom,
      email: from_email,
      name: from_name || 'Sender',
    },
    sender_raw: rawFrom,
    sender_email: from_email,
    sender_name: from_name || 'Sender',
    to: rawTo,
    to_email,
    recipient: {
      raw: rawTo,
      email: to_email,
    },
    recipient_raw: rawTo,
    recipient_email: to_email,
    reply_to,
    return_path,
    date,
    date_header: date || nowIso,
    message_id,
    body_plain: body_plain.trim(),
    body_html,
    attachments,
    extracted_urls,
    extracted_ips,
    extracted_domains: Array.from(extracted_domains),
    raw_eml_source: rawEml,
  };
}

export const parseRawEmail = parseEmailContent;

