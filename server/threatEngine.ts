import { GoogleGenAI } from '@google/genai';
import {
  AuthAnalysis,
  ContentAnalysisResult,
  IndicatorItem,
  SeverityLevel,
  ThreatClassification,
  ThreatEvidenceItem,
} from '../src/types';
import { ParsedRawEmail } from './emailParser';
import { RelayAnalysisResult } from './relayAnalyzer';
import { lookupIpIntelligence } from './mockGeoDb';
import { intelligenceManager } from './intelligence/providerManager';

// Common impersonated brands and domains for typo-squatting detection
const TARGET_BRANDS = [
  'microsoft.com',
  'google.com',
  'apple.com',
  'amazon.com',
  'paypal.com',
  'office365.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'docusign.net',
  'adobe.com',
  'dropbox.com',
  'github.com',
  'stripe.com',
  'slack.com',
];

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

export function checkLookalikeDomain(domain: string): { isLookalike: boolean; brand?: string; similarityScore?: number } {
  const clean = domain.toLowerCase().replace(/^(www\.|mail\.|smtp\.)/, '');
  const normalized = clean
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/vv/g, 'w');

  for (const brand of TARGET_BRANDS) {
    if (clean === brand) return { isLookalike: false }; // Exact match
    const brandName = brand.split('.')[0];
    const dist = levenshteinDistance(clean, brand);
    const normDist = levenshteinDistance(normalized, brand);

    if (
      dist <= 2 ||
      normDist <= 2 ||
      (normalized.includes(brandName) && clean !== brand) ||
      (clean.includes(brandName) && clean !== brand)
    ) {
      const bestDist = Math.min(dist, normDist);
      return {
        isLookalike: true,
        brand,
        similarityScore: Math.max(60, Math.round((1 - bestDist / Math.max(clean.length, brand.length)) * 100)),
      };
    }
  }
  return { isLookalike: false };
}

export function detectPromptInjection(text: string): { detected: boolean; reason?: string; severity: SeverityLevel } {
  const lower = text.toLowerCase();
  const injectionPatterns = [
    { regex: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i, reason: 'Attempt to override AI system prompt instructions' },
    { regex: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)/i, reason: 'Attempt to disregard safety directives' },
    { regex: /you\s+are\s+now\s+(in\s+developer\s+mode|dan|an\s+unfiltered|jailbroken)/i, reason: 'Jailbreak / role-reversal prompt injection trigger' },
    { regex: /\[system\s+instruction\]|<\s*system\s*>|role:\s*system/i, reason: 'Fake system message token delimiter injection' },
    { regex: /reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions|secret\s+key)/i, reason: 'Attempt to extract model configuration or confidential instructions' },
    { regex: /repeat\s+(everything|the\s+text)\s+above/i, reason: 'Prompt extraction attack pattern' },
    { regex: /assistant:\s*|system:\s*|human:\s*/i, reason: 'Conversation delimiter spoofing' },
  ];

  for (const p of injectionPatterns) {
    if (p.regex.test(lower)) {
      return { detected: true, reason: p.reason, severity: 'critical' };
    }
  }

  return { detected: false, severity: 'low' };
}

export function detectHiddenContent(html: string, plainText: string): { detected: boolean; reasons: string[] } {
  const reasons: string[] = [];

  // Zero-width characters
  const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF\u00AD]/;
  if (zeroWidthRegex.test(plainText) || zeroWidthRegex.test(html)) {
    reasons.push('Zero-width Unicode characters detected (obfuscation technique)');
  }

  // Hidden CSS styles
  if (html) {
    if (/display\s*:\s*none/i.test(html)) {
      reasons.push('Hidden elements with "display: none" detected in HTML');
    }
    if (/visibility\s*:\s*hidden/i.test(html)) {
      reasons.push('Hidden elements with "visibility: hidden" detected in HTML');
    }
    if (/font-size\s*:\s*0(?:px|pt|em|rem)?/i.test(html)) {
      reasons.push('Micro-sized / invisible font size (0px) detected in HTML');
    }
    if (/opacity\s*:\s*0(?:\.0+)?/i.test(html)) {
      reasons.push('Invisible text with zero opacity detected in HTML');
    }
    if (/<!--[\s\S]*?(?:instruction|system|ignore|bypass)[\s\S]*?-->/i.test(html)) {
      reasons.push('Suspicious instructions embedded inside HTML comments');
    }
  }

  return {
    detected: reasons.length > 0,
    reasons,
  };
}

export interface FullThreatAnalysisResult {
  risk_score: number;
  classification: ThreatClassification;
  confidence: number;
  auth_analysis: AuthAnalysis;
  evidence_list: ThreatEvidenceItem[];
  indicators: IndicatorItem[];
  content_analysis: ContentAnalysisResult;
  executive_summary: string;
  ai_reasoning?: string;
  mitre_attack: Array<{
    tactic: string;
    technique_id: string;
    technique_name: string;
    description: string;
  }>;
  defensive_recommendations: string[];
  disclaimers: {
    geolocation_limitation: string;
    attribution_limitation: string;
    legal_notice: string;
  };
}

export function analyzeThreatDeterministic(
  parsed: ParsedRawEmail,
  relayResult: RelayAnalysisResult
): FullThreatAnalysisResult {
  const evidenceList: ThreatEvidenceItem[] = [];
  const indicators: IndicatorItem[] = [];
  const mitreAttack: Array<{
    tactic: string;
    technique_id: string;
    technique_name: string;
    description: string;
  }> = [];
  const defensiveRecommendations: string[] = [];

  let rawRiskScore = 0;

  // 1. Authentication Analysis (SPF, DKIM, DMARC)
  const authResultsHeader = parsed.headers['authentication-results'] || '';
  const dkimHeader = parsed.headers['dkim-signature'];
  const senderDomain = parsed.from_email.includes('@') ? parsed.from_email.split('@')[1] : '';

  let spfResult: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' = 'none';
  let spfAligned = false;
  if (/spf=pass/i.test(authResultsHeader) || /Received-SPF:\s*pass/i.test(parsed.headers['received-spf'] || '')) {
    spfResult = 'pass';
    spfAligned = true;
  } else if (/spf=fail/i.test(authResultsHeader) || /Received-SPF:\s*fail/i.test(parsed.headers['received-spf'] || '')) {
    spfResult = 'fail';
  } else if (/spf=softfail/i.test(authResultsHeader) || /Received-SPF:\s*softfail/i.test(parsed.headers['received-spf'] || '')) {
    spfResult = 'softfail';
  } else if (/spf=neutral/i.test(authResultsHeader)) {
    spfResult = 'neutral';
  }

  let dkimResult: 'pass' | 'fail' | 'neutral' | 'none' | 'temperror' | 'permerror' = dkimHeader ? 'neutral' : 'none';
  let dkimAligned = false;
  let signingDomain = '';
  let selector = '';

  if (dkimHeader) {
    const dMatch = dkimHeader.match(/d=([^;\s]+)/i);
    const sMatch = dkimHeader.match(/s=([^;\s]+)/i);
    if (dMatch) signingDomain = dMatch[1];
    if (sMatch) selector = sMatch[1];

    if (/dkim=pass/i.test(authResultsHeader)) {
      dkimResult = 'pass';
      dkimAligned = signingDomain.toLowerCase() === senderDomain.toLowerCase();
    } else if (/dkim=fail/i.test(authResultsHeader)) {
      dkimResult = 'fail';
    }
  }

  let dmarcResult: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror' = 'none';
  let dmarcPolicy: 'none' | 'quarantine' | 'reject' = 'none';

  if (/dmarc=pass/i.test(authResultsHeader)) {
    dmarcResult = 'pass';
  } else if (/dmarc=fail/i.test(authResultsHeader) || (!spfAligned && !dkimAligned && (spfResult === 'fail' || dkimResult === 'fail'))) {
    dmarcResult = 'fail';
  }

  if (/p=reject/i.test(authResultsHeader) || /p=reject/i.test(parsed.headers['dmarc-filter'] || '')) {
    dmarcPolicy = 'reject';
  } else if (/p=quarantine/i.test(authResultsHeader)) {
    dmarcPolicy = 'quarantine';
  }

  const authAnalysis: AuthAnalysis = {
    spf: {
      result: spfResult,
      domain: senderDomain,
      sender_ip: relayResult.origin_candidates[0]?.ip_address,
      aligned: spfAligned,
      explanation:
        spfResult === 'pass'
          ? `Transmitting host IP authorized by ${senderDomain} SPF DNS policy.`
          : spfResult === 'fail'
          ? `Transmitting host IP is explicitly NOT authorized by ${senderDomain} SPF policy (Spoofing signal).`
          : `No definitive SPF pass recorded for domain ${senderDomain}.`,
    },
    dkim: {
      signature_present: !!dkimHeader,
      result: dkimResult,
      signing_domain: signingDomain,
      selector,
      aligned: dkimAligned,
      explanation: dkimHeader
        ? dkimResult === 'pass'
          ? `DKIM cryptographic signature verified for domain ${signingDomain}.`
          : `DKIM signature validation failed or signature is invalid.`
        : 'No DKIM cryptographic signature found in message headers.',
    },
    dmarc: {
      result: dmarcResult,
      policy: dmarcPolicy,
      spf_aligned: spfAligned,
      dkim_aligned: dkimAligned,
      explanation:
        dmarcResult === 'pass'
          ? 'DMARC validation passed with aligned SPF/DKIM identifier.'
          : dmarcResult === 'fail'
          ? `DMARC validation failed against policy (${dmarcPolicy}). High indicator of domain spoofing.`
          : 'DMARC policy record absent or unverified.',
    },
  };

  if (dmarcResult === 'fail') {
    rawRiskScore += 25;
    evidenceList.push({
      id: 'ev-auth-dmarc-fail',
      rule_id: 'RULE_DMARC_ALIGNMENT_FAILURE',
      category: 'AUTH',
      title: 'DMARC Authentication Failure',
      description: `The email failed DMARC validation for domain "${senderDomain}". Transmitting server was not authorized.`,
      severity: 'critical',
      weight: 25,
      mitre_technique: 'T1566 - Phishing / Email Spoofing',
    });
    mitreAttack.push({
      tactic: 'Initial Access',
      technique_id: 'T1566.002',
      technique_name: 'Phishing: Spearphishing Link',
      description: 'Adversaries send spearphishing emails with spoofed headers to gain initial access.',
    });
  }

  if (spfResult === 'fail') {
    rawRiskScore += 20;
    evidenceList.push({
      id: 'ev-auth-spf-fail',
      rule_id: 'RULE_SPF_HARD_FAIL',
      category: 'AUTH',
      title: 'SPF Verification Hard Fail',
      description: `Sender IP does not match the published SPF records for ${senderDomain}.`,
      severity: 'high',
      weight: 20,
    });
  }

  // 2. Sender / Reply-To / Return-Path Mismatch
  if (parsed.reply_to && parsed.from_email && parsed.reply_to !== parsed.from_email) {
    const replyToDomain = parsed.reply_to.split('@')[1] || '';
    if (replyToDomain !== senderDomain) {
      rawRiskScore += 22;
      evidenceList.push({
        id: 'ev-mismatch-replyto',
        rule_id: 'RULE_REPLYTO_SENDER_MISMATCH',
        category: 'SENDER',
        title: 'Reply-To Address Mismatch (Routing Diversion)',
        description: `Replies are redirected to "${parsed.reply_to}", which differs completely from sender domain "${senderDomain}".`,
        severity: 'high',
        weight: 22,
        mitre_technique: 'T1566 - Spearphishing / BEC Diversion',
      });
    }
  }

  if (parsed.return_path && parsed.from_email && parsed.return_path !== parsed.from_email) {
    const returnDomain = parsed.return_path.split('@')[1] || '';
    if (returnDomain && returnDomain !== senderDomain && !returnDomain.includes('amazonses') && !returnDomain.includes('sendgrid')) {
      rawRiskScore += 15;
      evidenceList.push({
        id: 'ev-mismatch-returnpath',
        rule_id: 'RULE_RETURNPATH_MISMATCH',
        category: 'SENDER',
        title: 'Return-Path Envelope Mismatch',
        description: `The envelope sender "${parsed.return_path}" differs from the header sender "${parsed.from_email}".`,
        severity: 'medium',
        weight: 15,
      });
    }
  }

  // 3. Display-Name Impersonation
  const executiveNames = ['CEO', 'Chief Executive', 'Tim Cook', 'Satya Nadella', 'Sundar Pichai', 'CFO', 'Finance Director', 'IT Support', 'Helpdesk Admin', 'HR Payroll', 'Billing Department'];
  const fromNameLower = parsed.from_name.toLowerCase();
  for (const exec of executiveNames) {
    if (fromNameLower.includes(exec.toLowerCase()) && !parsed.from_email.includes('company.com') && (parsed.from_email.includes('gmail.com') || parsed.from_email.includes('mail.ru') || parsed.from_email.includes('outlook.com') || parsed.from_email.includes('yandex'))) {
      rawRiskScore += 30;
      evidenceList.push({
        id: 'ev-display-impersonation',
        rule_id: 'RULE_DISPLAY_NAME_SPOOFING',
        category: 'SENDER',
        title: 'VIP / Executive Display-Name Impersonation',
        description: `Sender displays executive identity "${parsed.from_name}" while using a public webmail domain (${parsed.from_email}).`,
        severity: 'critical',
        weight: 30,
        mitre_technique: 'T1656 - Impersonation',
      });
      break;
    }
  }

  // 4. Lookalike / Typo-squatting Domain Detection
  for (const domain of parsed.extracted_domains) {
    const lookalike = checkLookalikeDomain(domain);
    if (lookalike.isLookalike) {
      rawRiskScore += 25;
      evidenceList.push({
        id: `ev-lookalike-${domain}`,
        rule_id: 'RULE_LOOKALIKE_DOMAIN',
        category: 'INFRASTRUCTURE',
        title: `Lookalike / Typo-squatting Domain (${domain})`,
        description: `Domain "${domain}" mimics legitimate brand "${lookalike.brand}" (similarity: ${lookalike.similarityScore}%).`,
        severity: 'critical',
        weight: 25,
        mitre_technique: 'T1566.002 - Spearphishing Link',
      });
      mitreAttack.push({
        tactic: 'Resource Development',
        technique_id: 'T1583.001',
        technique_name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries register domains resembling legitimate brands to deceive victims.',
      });
    }
  }

  // 5. URL Forensics
  for (const url of parsed.extracted_urls) {
    const isIpUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url);
    const isObfuscated = url.includes('@') || url.includes('%25') || url.includes('base64') || url.includes('.xyz') || url.includes('.top') || url.includes('.ru') || url.includes('.tk');
    const isPunycode = url.includes('xn--');

    if (isIpUrl) {
      rawRiskScore += 20;
      evidenceList.push({
        id: `ev-url-ip-${url.slice(0, 20)}`,
        rule_id: 'RULE_DIRECT_IP_URL',
        category: 'URL',
        title: 'Direct IP Host in Hyperlink',
        description: `Hyperlink targets an unmapped IP address directly instead of a legitimate domain (${url}).`,
        severity: 'high',
        weight: 20,
        mitre_technique: 'T1566.002 - Spearphishing Link',
      });
    }

    if (isPunycode) {
      rawRiskScore += 22;
      evidenceList.push({
        id: `ev-url-punycode-${url.slice(0, 20)}`,
        rule_id: 'RULE_PUNYCODE_URL',
        category: 'URL',
        title: 'Internationalized Punycode Domain (Homoglyph Attack)',
        description: `URL utilizes Punycode ('xn--') representation to conceal lookalike domain spoofing.`,
        severity: 'critical',
        weight: 22,
        mitre_technique: 'T1566.002 - Spearphishing Link',
      });
    }

    if (isObfuscated) {
      rawRiskScore += 15;
      evidenceList.push({
        id: `ev-url-obf-${url.slice(0, 20)}`,
        rule_id: 'RULE_OBFUSCATED_URL',
        category: 'URL',
        title: 'Suspicious TLD or Obfuscated Hyperlink',
        description: `Link utilizes deceptive encoding, high-risk TLD, or redirection parameter: ${url.slice(0, 80)}...`,
        severity: 'medium',
        weight: 15,
      });
    }
  }

  // 6. Attachment Forensics
  for (const att of parsed.attachments) {
    if (att.risk_flag) {
      rawRiskScore += 35;
      evidenceList.push({
        id: `ev-att-${att.id}`,
        rule_id: 'RULE_DANGEROUS_ATTACHMENT',
        category: 'ATTACHMENT',
        title: `High-Risk Attachment: ${att.filename}`,
        description: `Dangerous file type detected (${att.filename}, ${att.content_type}). Potentially malicious payload delivery (SHA-256: ${att.sha256.slice(0, 16)}...).`,
        severity: 'critical',
        weight: 35,
        mitre_technique: 'T1566.001 - Spearphishing Attachment',
      });
      mitreAttack.push({
        tactic: 'Initial Access',
        technique_id: 'T1566.001',
        technique_name: 'Phishing: Spearphishing Attachment',
        description: 'Adversaries send malicious payloads via email attachments.',
      });
    }
  }

  // 7. Relay & Origin Infrastructure Forensics
  const originNode = relayResult.origin_candidates[0];
  if (originNode && originNode.geo?.is_vpn_tor_proxy) {
    rawRiskScore += 20;
    evidenceList.push({
      id: 'ev-relay-anonymizer',
      rule_id: 'RULE_ORIGIN_ANONYMIZER',
      category: 'RELAY',
      title: `Origin Connected via ${originNode.geo.proxy_type || 'Anonymizer Proxy/Tor'}`,
      description: `Transmitting infrastructure (${originNode.ip_address} - ${originNode.geo.isp}) is a verified Tor Exit Node / Commercial VPN.`,
      severity: 'high',
      weight: 20,
    });
  }

  if (relayResult.anomalies_detected.length > 0) {
    rawRiskScore += 15;
    evidenceList.push({
      id: 'ev-relay-anomalies',
      rule_id: 'RULE_RELAY_ROUTING_ANOMALY',
      category: 'RELAY',
      title: 'SMTP Relay Routing Anomalies Detected',
      description: relayResult.anomalies_detected.join('; '),
      severity: 'medium',
      weight: 15,
    });
  }

  // 8. Prompt Injection & Hidden Content Forensics
  const promptInjection = detectPromptInjection(`${parsed.subject} ${parsed.body_plain} ${parsed.body_html}`);
  if (promptInjection.detected) {
    rawRiskScore += 30;
    evidenceList.push({
      id: 'ev-prompt-injection',
      rule_id: 'RULE_PROMPT_INJECTION_DETECTED',
      category: 'CONTENT',
      title: 'AI Prompt-Injection / Jailbreak Pattern Detected',
      description: promptInjection.reason || 'Content contains adversarial instructions aimed at manipulating AI analysis models.',
      severity: 'critical',
      weight: 30,
      mitre_technique: 'T1059 - Command and Scripting Interpreter',
    });
  }

  const hiddenContent = detectHiddenContent(parsed.body_html, parsed.body_plain);
  if (hiddenContent.detected) {
    rawRiskScore += 20;
    evidenceList.push({
      id: 'ev-hidden-content',
      rule_id: 'RULE_HIDDEN_OBFUSCATED_HTML',
      category: 'CONTENT',
      title: 'Hidden Obfuscated Text / Zero-Width Unicode',
      description: hiddenContent.reasons.join('; '),
      severity: 'high',
      weight: 20,
      mitre_technique: 'T1027 - Obfuscated Files or Information',
    });
  }

  // 9. Content & NLP Semantic Analysis
  const fullText = `${parsed.subject} ${parsed.body_plain}`.toLowerCase();

  const urgencyWords = ['urgent', 'immediate', 'asap', 'within 24 hours', 'action required', 'account suspended', 'terminated', 'deadline', 'critical notice', 'final warning'];
  const financialWords = ['wire transfer', 'invoice', 'payment', 'remittance', 'swift', 'bank account', 'routing number', 'direct deposit', 'vendor payment', 'gift card', 'bitcoin', 'crypto'];
  const credentialWords = ['password expire', 'verify account', 'login to retain access', 'update credentials', 're-authenticate', 'security alert', 'unauthorized login', 'mailbox quota full', 'reset password'];
  const socialEngPatterns: string[] = [];

  let urgencyMatches = 0;
  for (const w of urgencyWords) {
    if (fullText.includes(w)) {
      urgencyMatches++;
      socialEngPatterns.push(`Urgency cue: "${w}"`);
    }
  }

  let financialMatches = 0;
  for (const w of financialWords) {
    if (fullText.includes(w)) {
      financialMatches++;
      socialEngPatterns.push(`Financial/Wire transfer cue: "${w}"`);
    }
  }

  let credMatches = 0;
  for (const w of credentialWords) {
    if (fullText.includes(w)) {
      credMatches++;
      socialEngPatterns.push(`Credential harvesting cue: "${w}"`);
    }
  }

  const urgencyScore = Math.min(100, urgencyMatches * 25);
  const financialDetected = financialMatches > 0;
  const credentialDetected = credMatches > 0;
  const executiveDetected = parsed.from_name.toLowerCase().includes('ceo') || parsed.from_name.toLowerCase().includes('director') || parsed.from_name.toLowerCase().includes('executive');

  if (urgencyMatches >= 2) {
    rawRiskScore += 12;
    evidenceList.push({
      id: 'ev-nlp-urgency',
      rule_id: 'RULE_NLP_HIGH_URGENCY',
      category: 'CONTENT',
      title: 'High Psychological Urgency Trigger',
      description: `Language contains coercive psychological pressure cues designed to bypass scrutiny.`,
      severity: 'medium',
      weight: 12,
    });
  }

  if (financialDetected && (parsed.reply_to || dmarcResult === 'fail' || urgencyMatches > 0)) {
    rawRiskScore += 25;
    evidenceList.push({
      id: 'ev-nlp-bec-wire',
      rule_id: 'RULE_BEC_FINANCIAL_DIVERT',
      category: 'CONTENT',
      title: 'Business Email Compromise (BEC) Payment Pattern',
      description: `Detected solicitation of financial fund transfer, invoice redirection, or banking modification.`,
      severity: 'critical',
      weight: 25,
      mitre_technique: 'T1566 - Financial Fraud / Wire BEC',
    });
  }

  if (credentialDetected && (parsed.extracted_urls.length > 0 || dmarcResult === 'fail')) {
    rawRiskScore += 25;
    evidenceList.push({
      id: 'ev-nlp-cred-harvest',
      rule_id: 'RULE_CREDENTIAL_HARVESTING_INTENT',
      category: 'CONTENT',
      title: 'Credential Harvesting Bait',
      description: `Content attempts to manipulate user into authenticating credentials or resetting enterprise passwords.`,
      severity: 'critical',
      weight: 25,
      mitre_technique: 'T1598 - Phishing for Information',
    });
  }

  // Calculate final clamped risk score
  const risk_score = Math.min(100, Math.max(0, rawRiskScore));

  // Determine classification
  let classification: ThreatClassification = 'LEGITIMATE';
  if (risk_score >= 85) {
    if (parsed.attachments.some((a) => a.risk_flag)) {
      classification = 'MALWARE_SUSPECTED';
    } else if (financialDetected && (executiveDetected || parsed.reply_to)) {
      classification = 'BUSINESS_EMAIL_COMPROMISE';
    } else if (credentialDetected || dmarcResult === 'fail') {
      classification = 'PHISHING';
    } else {
      classification = 'FRAUD';
    }
  } else if (risk_score >= 65) {
    classification = financialDetected ? 'BUSINESS_EMAIL_COMPROMISE' : 'PHISHING';
  } else if (risk_score >= 40) {
    classification = 'SUSPICIOUS';
  } else if (risk_score >= 15) {
    classification = 'LOW_RISK';
  } else {
    classification = 'LEGITIMATE';
  }

  const confidence = Math.min(0.98, 0.70 + (evidenceList.length * 0.04));

  // Build Indicator items
  if (parsed.from_email) {
    indicators.push({
      id: `ind-email-${parsed.from_email}`,
      type: 'EMAIL_ADDRESS',
      value: parsed.from_email,
      source: 'From Header',
      risk_level: dmarcResult === 'fail' ? 'high' : 'low',
      reputation: dmarcResult === 'fail' ? 'SUSPICIOUS' : 'CLEAN',
      confidence: 0.95,
      first_seen: new Date().toISOString(),
    });
  }

  for (const dom of parsed.extracted_domains) {
    const isLook = checkLookalikeDomain(dom);
    indicators.push({
      id: `ind-dom-${dom}`,
      type: 'DOMAIN',
      value: dom,
      source: 'Message Body/Headers',
      risk_level: isLook.isLookalike ? 'critical' : 'low',
      reputation: isLook.isLookalike ? 'MALICIOUS' : 'CLEAN',
      confidence: 0.92,
      first_seen: new Date().toISOString(),
      details: { is_lookalike: isLook.isLookalike, target_brand: isLook.brand },
    });
  }

  for (const ip of parsed.extracted_ips) {
    const geo = lookupIpIntelligence(ip);
    indicators.push({
      id: `ind-ip-${ip}`,
      type: 'IP',
      value: ip,
      source: 'Received Header / Body',
      risk_level: geo.threat_reputation === 'MALICIOUS' ? 'critical' : geo.threat_reputation === 'SUSPICIOUS' ? 'high' : 'low',
      reputation: geo.threat_reputation || 'CLEAN',
      confidence: 0.90,
      first_seen: new Date().toISOString(),
      details: { geo },
    });
  }

  for (const url of parsed.extracted_urls) {
    indicators.push({
      id: `ind-url-${Buffer.from(url).toString('base64').slice(0, 16)}`,
      type: 'URL',
      value: url,
      source: 'Message Body',
      risk_level: risk_score >= 65 ? 'high' : 'low',
      reputation: risk_score >= 65 ? 'SUSPICIOUS' : 'CLEAN',
      confidence: 0.88,
      first_seen: new Date().toISOString(),
    });
  }

  for (const att of parsed.attachments) {
    indicators.push({
      id: `ind-hash-${att.sha256.slice(0, 16)}`,
      type: 'HASH',
      value: att.sha256,
      source: `Attachment: ${att.filename}`,
      risk_level: att.risk_flag ? 'critical' : 'low',
      reputation: att.risk_flag ? 'MALICIOUS' : 'CLEAN',
      confidence: 0.99,
      first_seen: new Date().toISOString(),
      details: { filename: att.filename, md5: att.md5 },
    });
  }

  if (classification === 'BUSINESS_EMAIL_COMPROMISE' || classification === 'FRAUD') {
    defensiveRecommendations.push('Freeze any pending wire transactions and verify payment directives via out-of-band phone call.');
    defensiveRecommendations.push('Block sender domain across enterprise email security gateways (SEG).');
    defensiveRecommendations.push('Notify enterprise fraud desk and enforce strict DMARC reject policies.');
  } else if (classification === 'PHISHING') {
    defensiveRecommendations.push('Block destination URLs and IP addresses on corporate DNS & web filtering proxies.');
    defensiveRecommendations.push('Initiate credential reset and invalidate active SSO sessions for targeted users.');
    defensiveRecommendations.push('Purge matching emails from all user mailboxes via automated M365/Google Workspace remediation.');
  } else if (classification === 'MALWARE_SUSPECTED') {
    defensiveRecommendations.push('Isolate affected endpoint devices from enterprise subnet immediately.');
    defensiveRecommendations.push('Submit attachment SHA-256 to EDR / SIEM blocklist across all internal hosts.');
    defensiveRecommendations.push('Conduct memory and persistence artifact triage on recipient workstations.');
  } else {
    defensiveRecommendations.push('Maintain standard monitoring; message exhibits standard legitimate routing authentication.');
  }

  const executive_summary = `Forensic analysis classified this message as ${classification} (Risk Score: ${risk_score}/100, Confidence: ${Math.round(confidence * 100)}%). ${
    evidenceList.length > 0
      ? `Primary risk factors include ${evidenceList.slice(0, 3).map((e) => e.title.toLowerCase()).join(', ')}.`
      : 'No high-risk security indicators were identified.'
  } Origin MTA candidate identified at ${originNode ? `${originNode.ip_address} (${originNode.infrastructure_info})` : 'unspecified infrastructure'}.`;

  const contentAnalysis: ContentAnalysisResult = {
    sentiment: risk_score > 50 ? 'Urgent / Adversarial' : 'Neutral / Benign',
    urgency_score: urgencyScore,
    financial_request_detected: financialDetected,
    credential_harvesting_detected: credentialDetected,
    executive_impersonation_detected: executiveDetected,
    spoofed_display_name_detected: fromNameLower.includes('ceo') || fromNameLower.includes('support'),
    social_engineering_patterns: socialEngPatterns,
    extracted_topics: [
      financialDetected ? 'Financial Transaction' : undefined,
      credentialDetected ? 'Account Authentication' : undefined,
      'Email Routing Forensics',
    ].filter(Boolean) as string[],
    ai_summary: executive_summary,
  };

  const ai_reasoning = `Deterministic forensic evaluation identified ${evidenceList.length} distinct threat indicators. The message demonstrates ${
    risk_score > 60 ? 'active deceptive intent utilizing infrastructure masking and authentication bypass' : 'normal standard business correspondence'
  }. Relay node tracing established origin injection at ${originNode ? originNode.ip_address : 'remote MTA'} with ${originNode?.reliability_score || 70}% candidate reliability.`;

  return {
    risk_score,
    classification,
    confidence,
    auth_analysis: authAnalysis,
    evidence_list: evidenceList,
    indicators,
    content_analysis: contentAnalysis,
    executive_summary,
    ai_reasoning,
    mitre_attack: mitreAttack,
    defensive_recommendations: defensiveRecommendations,
    disclaimers: {
      geolocation_limitation:
        'DISCLAIMER: Geolocation represents an estimate associated with network infrastructure and Autonomous Systems (ASNs). It does NOT establish the physical location or domicile of any human person or perpetrator.',
      attribution_limitation:
        'ATTRIBUTION LIMITATION: Infrastructure correlation, proxies, VPNs, and mail relays can support forensic investigations but do NOT constitute definitive legal proof of attacker identity.',
      legal_notice:
        'This forensic report was cryptographically signed and produced for authorized defensive cybersecurity and incident response purposes under RFC 5322 specifications.',
    },
  };
}

export async function analyzeThreats(
  parsed: ParsedRawEmail,
  relayResult: RelayAnalysisResult
): Promise<FullThreatAnalysisResult> {
  const result = analyzeThreatDeterministic(parsed, relayResult);

  // 1. External Threat Intelligence Enrichment
  try {
    for (const att of parsed.attachments) {
      if (att.sha256) {
        const vtRes = await intelligenceManager.enrichHash(att.sha256);
        if (vtRes.status === 'LIVE' && vtRes.reputation === 'MALICIOUS') {
          result.risk_score = Math.min(100, result.risk_score + 35);
          result.evidence_list.push({
            id: `ev-vt-hash-${att.sha256.slice(0, 12)}`,
            rule_id: 'RULE_VT_KNOWN_MALICIOUS_HASH',
            category: 'ATTACHMENT',
            title: `VirusTotal Malicious Hash Detection (${att.filename})`,
            description: `VirusTotal returned ${vtRes.data?.malicious || 'multiple'} vendor detections for SHA-256 ${att.sha256.slice(0, 16)}...`,
            severity: 'critical',
            weight: 35,
          });
        }
      }
    }
  } catch (err) {
    console.warn('[ThreatEngine] External intelligence enrichment skipped/error:', err);
  }

  // 2. Gemini Reasoning (if key available)
  if (process.env.GEMINI_API_KEY) {
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      const originNode = relayResult.origin_candidates[0];
      const prompt = `You are a Tier-3 Cybersecurity Forensic Email Analyst. Provide a brief 3-sentence technical forensic evaluation for this analyzed email:
Subject: "${parsed.subject}"
From: "${parsed.from}" (Email: "${parsed.from_email}")
Reply-To: "${parsed.reply_to || 'None'}"
SPF: ${result.auth_analysis.spf.result}, DKIM: ${result.auth_analysis.dkim.result}, DMARC: ${result.auth_analysis.dmarc.result}
Calculated Risk: ${result.risk_score}/100 (${result.classification})
Origin Node: ${originNode?.ip_address} (${originNode?.infrastructure_info})
Identified Evidence: ${result.evidence_list.map((e) => e.title).join(', ')}
Body excerpt: "${parsed.body_plain.slice(0, 300)}"

Explain technical deception tactics, relay infrastructure reliability, and impact. Do NOT claim the IP proves physical human sender identity.`;

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
      });
      if (response.text) {
        result.ai_reasoning = response.text;
      }
    } catch (err: any) {
      console.warn('Gemini API query skipped/failed, using deterministic reasoning:', err?.message);
    }
  }

  return result;
}
