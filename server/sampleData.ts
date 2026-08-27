export interface PresetSample {
  id: string;
  name: string;
  category: string;
  description: string;
  eml: string;
}

export const PRESET_SAMPLES: PresetSample[] = [
  {
    id: 'sample-bec-ceo',
    name: 'BEC: CEO Urgent Wire Transfer Request',
    category: 'BUSINESS_EMAIL_COMPROMISE',
    description: 'CEO display-name spoofing with reply-to routing diversion and confidential fund transfer solicitation through Tor exit relay.',
    eml: `Received: from mail.corporate-gateway.internal (10.0.4.15) by mx1.company.com with ESMTP id 98124; Wed, 26 Aug 2026 09:14:22 +0000
Received: from tor-relay-frankfurt.zwiebelfreunde.de ([185.220.101.5]) by mail.corporate-gateway.internal with ESMTPS (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384) id 55431 for <cfo-finance@acme-corp.com>; Wed, 26 Aug 2026 09:14:18 +0000
Received: from desktop-agent-x9.lan (192.168.1.104) by tor-relay-frankfurt.zwiebelfreunde.de with ESMTPA id 11029; Wed, 26 Aug 2026 09:14:10 +0000
Authentication-Results: mx1.company.com;
  spf=fail (sender IP 185.220.101.5 is not allowed by domain acme-corp.com) smtp.mailfrom=ceo-direct-office@gmail.com;
  dkim=none;
  dmarc=fail (p=reject dis=none) header.from=acme-corp.com
From: "Rajesh Sharma (CEO)" <rajesh.sharma@acme-corp.com>
To: "Finance Team" <cfo-finance@acme-corp.com>
Reply-To: executive-secure-desk@protonmail.ch
Return-Path: <bounce-daemon@unauthorized-mta.ru>
Subject: URGENT: Confidential Acquisition Wire Transfer - Immediate Action Required
Date: Wed, 26 Aug 2026 09:14:05 +0000
Message-ID: <ceo-urgent-994812@acme-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Hi Team,

I am currently in an executive board meeting with our M&A legal advisors and cannot take phone calls right now.

We have reached the closing phase for our strategic overseas acquisition. I need an urgent wire transfer of $84,500 processed before 12:00 PM today to secure the transaction Escrow.

Please reply to my confidential desk (executive-secure-desk@protonmail.ch) right away so I can provide the updated beneficiary bank routing and SWIFT remittance instructions. Treat this matter with strict confidentiality until we issue the formal press release.

Best regards,

Rajesh Sharma
Chief Executive Officer | Acme Enterprise Global
Mobile (Unavailable): +1 (555) 019-2834
`,
  },
  {
    id: 'sample-phish-m365',
    name: 'Phishing: Microsoft 365 Password Expiration Bait',
    category: 'PHISHING',
    description: 'Lookalike domain (micr0soft-security-portal.co) targeting corporate SSO credentials with countdown pressure and failed DMARC.',
    eml: `Received: from protection.outlook.com (40.92.74.45) by mx.enterprise.com with ESMTPS id 77123; Wed, 26 Aug 2026 08:30:10 +0000
Received: from bulletproof-vps.moscow.ru ([194.26.29.112]) by protection.outlook.com with ESMTP id 88419 for <security@target-company.com>; Wed, 26 Aug 2026 08:30:02 +0000
Authentication-Results: mx.enterprise.com;
  spf=fail (sender IP 194.26.29.112 not permitted by domain microsoft.com);
  dkim=fail;
  dmarc=fail (p=reject) header.from=microsoft.com
From: "Microsoft Security Team" <no-reply@microsoft.com>
To: <target-user@company.com>
Reply-To: admin-verify@micr0soft-security-portal.co
Subject: Security Alert: Your Microsoft 365 Password Will Expire in 24 Hours
Date: Wed, 26 Aug 2026 08:29:55 +0000
Message-ID: <m365-sec-alert-88219@microsoft.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px;">
    <h2 style="color: #0078d4;">Microsoft Security Notification</h2>
    <p>Dear Valued User,</p>
    <p>Your enterprise Microsoft 365 authentication certificate and password will expire in <strong>24 hours</strong>. Failure to update credentials will result in immediate termination of Outlook, OneDrive, and Teams access.</p>
    <p>To retain uninterrupted access, please verify your account and keep your current password by authenticating through our secure gateway below:</p>
    <p style="text-align: center; margin: 30px 0;">
      <a href="http://194.26.29.112/auth/login?tenant=office365&redirect=http://micr0soft-security-portal.co/verify" style="background-color: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold;">Keep Same Password & Verify Account</a>
    </p>
    <p style="font-size: 12px; color: #777;">Microsoft Corporation | One Microsoft Way, Redmond, WA 98052</p>
  </div>
</body>
</html>
`,
  },
  {
    id: 'sample-malware-iso',
    name: 'Malware: Overdue Invoice with Payload (.ISO Attachment)',
    category: 'MALWARE_SUSPECTED',
    description: 'Deceptive invoice notice carrying an executable ISO container designed to bypass Windows Mark of the Web (MotW).',
    eml: `Received: from mail-relay.alexhost.nl ([45.154.255.89]) by mx.customer.org with ESMTPS id 33419; Wed, 26 Aug 2026 07:15:30 +0000
Authentication-Results: mx.customer.org;
  spf=softfail;
  dkim=none;
  dmarc=fail (p=none) header.from=global-logistics-corp.com
From: "Billing Department" <accounts@global-logistics-corp.com>
To: <accounting@customer.org>
Subject: Past Due Notice: Final Demand for Payment (Invoice_INV-889102.iso Attached)
Date: Wed, 26 Aug 2026 07:15:18 +0000
Message-ID: <inv-demand-2026-99128@global-logistics-corp.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====_NextPart_998124_===="

--====_NextPart_998124_====
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Please find attached our final overdue invoice #INV-889102.

If payment is not confirmed within 48 hours, interest penalties will accrue and legal collection proceedings will commence.

Download and inspect the attached invoice container file to verify payment instructions.

Finance Accounts Department
Global Logistics Corp.

--====_NextPart_998124_====
Content-Type: application/x-iso9660-image; name="Invoice_INV-889102.iso"
Content-Disposition: attachment; filename="Invoice_INV-889102.iso"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAH8F4mQAAAAAAAAAAOAADwELAQYAACAAAAAGAAAAAAAAAAAA
==
--====_NextPart_998124_====--
`,
  },
  {
    id: 'sample-legit-ses',
    name: 'Legitimate: AWS Developer Digest Newsletter',
    category: 'LEGITIMATE',
    description: 'Clean legitimate multi-hop enterprise newsletter passing SPF, DKIM 2048-bit signature, and DMARC reject alignment.',
    eml: `Received: from mail-sor-f41.google.com (209.85.220.41) by mx.google.com with SMTPS id 198234; Wed, 26 Aug 2026 06:00:15 +0000
Received: from a9-112.smtp-out.amazonses.com ([54.240.9.112]) by mail-sor-f41.google.com with ESMTPS (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384) id 44102 for <developer@corp.com>; Wed, 26 Aug 2026 06:00:12 +0000
Authentication-Results: mx.google.com;
  spf=pass (google.com: domain of 0100018f-ses@amazonses.com designates 54.240.9.112 as permitted sender) smtp.mailfrom=0100018f-ses@amazonses.com;
  dkim=pass header.i=@aws.amazon.com header.s=ses2026;
  dmarc=pass (p=reject dis=none) header.from=aws.amazon.com
DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=ses2026; d=aws.amazon.com; t=1756200000;
  h=From:To:Subject:Date:Message-ID:MIME-Version:Content-Type;
  bh=9xKpL01948xZ98104=; b=Kp9184810294198294109824091823098123==
From: "Amazon Web Services" <no-reply@aws.amazon.com>
To: <developer@corp.com>
Subject: AWS Weekly Architecture Digest: Building Resilient Multi-Region Applications
Date: Wed, 26 Aug 2026 06:00:05 +0000
Message-ID: <0100018f-ses-weekly-digest@email.amazonses.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: sans-serif; color: #232f3e; line-height: 1.6; padding: 20px;">
  <h2>AWS Architecture Highlights</h2>
  <p>Hello Builder,</p>
  <p>In this edition of the Architecture Digest, we explore best practices for deploying fault-tolerant distributed workloads across Amazon CloudFront, AWS Lambda, and DynamoDB Global Tables.</p>
  <p><a href="https://aws.amazon.com/blogs/architecture/resilient-design-patterns/" style="color: #ff9900; font-weight: bold;">Read the full technical whitepaper &rarr;</a></p>
  <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
  <p style="font-size: 12px; color: #888;">You are receiving this because you subscribed to AWS Developer Updates. Amazon Web Services, Inc., 410 Terry Ave. North, Seattle, WA 98109.</p>
</body>
</html>
`,
  },
];
