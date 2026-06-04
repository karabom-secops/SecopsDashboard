-- GRC & Insurability Module Migration
-- Run once: psql -d secops -f migrate-grc.sql

-- ── Schema ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS grc_questions (
  id           SERIAL PRIMARY KEY,
  section      VARCHAR(100) NOT NULL,
  order_num    INT          NOT NULL,
  text         TEXT         NOT NULL,
  weight       VARCHAR(20)  NOT NULL DEFAULT 'medium',
  help_text    TEXT,
  itoo_ref     VARCHAR(80),
  nist_ref     VARCHAR(80)
);

CREATE TABLE IF NOT EXISTS grc_assessments (
  id           SERIAL PRIMARY KEY,
  tenant_id    INT REFERENCES tenants(id) ON DELETE CASCADE,
  assessed_at  TIMESTAMPTZ DEFAULT NOW(),
  assessed_by  INT REFERENCES users(id) ON DELETE SET NULL,
  grc_score    INT CHECK (grc_score BETWEEN 0 AND 100),
  UNIQUE(tenant_id)
);

CREATE TABLE IF NOT EXISTS grc_answers (
  id             SERIAL PRIMARY KEY,
  assessment_id  INT REFERENCES grc_assessments(id) ON DELETE CASCADE,
  question_id    INT REFERENCES grc_questions(id),
  answer         VARCHAR(10) CHECK (answer IN ('yes','partial','no','na')),
  notes          TEXT,
  UNIQUE(assessment_id, question_id)
);

CREATE INDEX IF NOT EXISTS idx_grc_assessments_tenant ON grc_assessments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_grc_answers_assessment ON grc_answers(assessment_id);

-- ── Question Bank ─────────────────────────────────────────────────────────────
-- Only insert if the table is empty (idempotent re-run)

INSERT INTO grc_questions (section, order_num, text, weight, help_text, itoo_ref, nist_ref)
SELECT * FROM (VALUES

  -- ── Identity & Access Management ──────────────────────────────────────────
  ('Identity & Access Management', 1,
   'Is multi-factor authentication (MFA) enforced for all administrator and privileged accounts?',
   'critical',
   'MFA for admin accounts is a top insurer requirement. SMS OTP, authenticator apps, and hardware tokens all qualify.',
   'Security Policies §10', 'PR.AC-7'),

  ('Identity & Access Management', 2,
   'Is MFA enforced for all employee remote access (VPN, RDP, remote desktop)?',
   'critical',
   'Remote access without MFA is the most common ransomware entry point.',
   'Security Policies §10', 'PR.AC-3'),

  ('Identity & Access Management', 3,
   'Is MFA enforced for cloud/SaaS services (e.g. Microsoft 365, Google Workspace)?',
   'critical',
   'Business email compromise via O365 is highly prevalent.',
   'Security Policies §10', 'PR.AC-7'),

  ('Identity & Access Management', 4,
   'Do you apply the principle of least privilege — users only have the access required for their role?',
   'high',
   'Users should not have admin rights on their own workstations unless required.',
   'Access Management §1', 'PR.AC-4'),

  ('Identity & Access Management', 5,
   'Do you review and revoke user access within 24 hours of employee termination?',
   'high',
   'Stale accounts are a common insider threat and audit finding.',
   'Access Management §5', 'PR.AC-1'),

  ('Identity & Access Management', 6,
   'Are privileged/admin account credentials stored in a password vault (PAM solution)?',
   'high',
   'Examples: CyberArk, HashiCorp Vault, Keeper, 1Password Teams.',
   'Access Management §11', 'PR.AC-7'),

  ('Identity & Access Management', 7,
   'Do you enforce a strong password policy (minimum length, complexity, no known weak passwords)?',
   'medium',
   'Minimum 12 characters with complexity or passphrases strongly recommended.',
   'Security Policies §10', 'PR.AC-7'),

  -- ── Vulnerability & Patch Management ──────────────────────────────────────
  ('Vulnerability & Patch Management', 1,
   'Do you have a documented vulnerability and patch management policy?',
   'high',
   'Policy should define SLAs: critical patches within 14–30 days, high within 60 days.',
   'Patch & Vulnerability §1', 'ID.RA-1'),

  ('Vulnerability & Patch Management', 2,
   'Are critical patches (CVSS 9.0–10.0) applied within 30 days of release?',
   'critical',
   'Unpatched critical vulnerabilities are a primary underwriting concern.',
   'Patch & Vulnerability §6', 'PR.IP-12'),

  ('Vulnerability & Patch Management', 3,
   'Are high-severity patches (CVSS 7.0–8.9) applied within 60 days of release?',
   'high',
   NULL,
   'Patch & Vulnerability §6', 'PR.IP-12'),

  ('Vulnerability & Patch Management', 4,
   'Do you perform regular vulnerability scanning of your internal and external environments?',
   'high',
   'At minimum quarterly external scanning; monthly preferred.',
   'Patch & Vulnerability §3', 'ID.RA-1'),

  ('Vulnerability & Patch Management', 5,
   'Has your environment been subjected to penetration testing within the past 12 months?',
   'high',
   'Third-party penetration testing provides evidence of security posture for insurers.',
   'Patch & Vulnerability §2', 'ID.RA-1'),

  ('Vulnerability & Patch Management', 6,
   'Were all serious findings from the last penetration test or vulnerability scan remediated?',
   'critical',
   'Outstanding critical/high findings significantly impact insurability.',
   'Patch & Vulnerability §2', 'RS.MI-3'),

  -- ── Security Monitoring & Detection ───────────────────────────────────────
  ('Security Monitoring & Detection', 1,
   'Do you have a SIEM (Security Information & Event Management) solution in place?',
   'high',
   'Examples: Microsoft Sentinel, Splunk, IBM QRadar, Wazuh.',
   'Security Implementation §2', 'DE.CM-1'),

  ('Security Monitoring & Detection', 2,
   'Do you have 24/7 proactive monitoring of critical systems (SOC or MDR service)?',
   'critical',
   'Round-the-clock monitoring significantly reduces mean time to detect (MTTD).',
   'Security Implementation §2', 'DE.CM-1'),

  ('Security Monitoring & Detection', 3,
   'Are audit logs retained for a minimum of 90 days and analysed for anomalies?',
   'high',
   'Log retention is required for forensic investigation after an incident.',
   'Security Policies §11', 'DE.AE-3'),

  ('Security Monitoring & Detection', 4,
   'Do you have endpoint detection and response (EDR/XDR) deployed on all endpoints?',
   'high',
   'EDR goes beyond traditional AV to detect fileless and behavioural threats.',
   'Security Implementation §11', 'DE.CM-4'),

  ('Security Monitoring & Detection', 5,
   'Do you have email security controls (SPF, DKIM, DMARC, anti-phishing) configured?',
   'high',
   'All three DNS records (SPF, DKIM, DMARC) should be configured and in enforcement mode.',
   'Security Implementation §11', 'PR.AT-1'),

  -- ── Incident Response ──────────────────────────────────────────────────────
  ('Incident Response', 1,
   'Do you have a documented incident response plan with defined roles and responsibilities?',
   'critical',
   'Insurers require evidence of an IR plan. It must name specific people, not just titles.',
   'IR & BCP §2', 'RS.RP-1'),

  ('Incident Response', 2,
   'Has the incident response plan been tested or exercised in the past 12 months?',
   'high',
   'Tabletop exercises qualify. Untested plans often fail in real incidents.',
   'IR & BCP §2', 'RS.IM-1'),

  ('Incident Response', 3,
   'Do you maintain a log of all security incidents, near-misses, and data breaches?',
   'medium',
   'Required for regulatory compliance (POPIA, GDPR) and insurance claims.',
   'IR & BCP §3', 'RS.AN-1'),

  ('Incident Response', 4,
   'Do you have cyber incident response retainer with a specialist firm or your insurer''s panel?',
   'medium',
   'Having a pre-agreed retainer reduces response time and cost significantly.',
   NULL, 'RS.CO-5'),

  -- ── Data Protection ────────────────────────────────────────────────────────
  ('Data Protection', 1,
   'Is sensitive data encrypted at rest (databases, file servers, cloud storage)?',
   'high',
   'AES-256 is the standard. Encryption at rest protects against physical theft and cloud breaches.',
   'Sensitive & Private Info §6', 'PR.DS-1'),

  ('Data Protection', 2,
   'Is sensitive data encrypted in transit (TLS 1.2+ for all external communications)?',
   'high',
   'All web services should enforce HTTPS. Internal services handling PII should also use TLS.',
   'Sensitive & Private Info §6', 'PR.DS-2'),

  ('Data Protection', 3,
   'Do you have a data classification policy defining how sensitive data must be handled?',
   'medium',
   'Classification tiers typically: Public, Internal, Confidential, Restricted.',
   'Security Policies §7', 'ID.AM-5'),

  ('Data Protection', 4,
   'Have you disabled USB/removable media write access on employee workstations?',
   'medium',
   'Data exfiltration via USB is a common insider threat vector.',
   'Sensitive & Private Info §5', 'PR.DS-5'),

  ('Data Protection', 5,
   'Do you comply with applicable data protection legislation (POPIA, GDPR, etc.)?',
   'high',
   'Non-compliance creates regulatory liability in addition to cyber risk.',
   'Security Policies §6', 'GV.PO-1'),

  -- ── Business Continuity & Backup ──────────────────────────────────────────
  ('Business Continuity & Backup', 1,
   'Do you maintain at least one offline or immutable backup that cannot be encrypted by ransomware?',
   'critical',
   'Air-gapped, offline, or immutable (object-lock) backups are the primary ransomware recovery control.',
   'IR & BCP §7', 'RC.RP-1'),

  ('Business Continuity & Backup', 2,
   'Are backups generated at least daily for critical systems?',
   'high',
   'RTO/RPO targets should drive backup frequency.',
   'IR & BCP §7', 'PR.IP-4'),

  ('Business Continuity & Backup', 3,
   'Are backup restoration procedures tested at least annually?',
   'high',
   'Untested backups frequently fail when needed. Insurers ask for evidence of restoration testing.',
   'IR & BCP §9', 'RC.IM-1'),

  ('Business Continuity & Backup', 4,
   'Do you have a documented business continuity / disaster recovery plan?',
   'high',
   'BC/DR plans should define RTO, RPO, and recovery priorities.',
   'IR & BCP §4', 'RC.RP-1'),

  ('Business Continuity & Backup', 5,
   'Can your organisation resume critical operations within 24 hours of a major cyber incident?',
   'critical',
   'Insurers use this to estimate business interruption exposure.',
   'IR & BCP §4', 'RC.RP-1'),

  -- ── Third Party Risk ───────────────────────────────────────────────────────
  ('Third Party Risk', 1,
   'Do contracts with third-party vendors require them to maintain security standards equivalent to yours?',
   'high',
   'Supply chain attacks are increasingly common. Contractual security requirements are an insurer expectation.',
   'Third Party §2', 'ID.SC-3'),

  ('Third Party Risk', 2,
   'Do you perform annual security reviews or assessments of critical third-party suppliers?',
   'medium',
   'Questionnaires, SOC 2 reports, and ISO 27001 certificates are acceptable forms of evidence.',
   'Third Party §3', 'ID.SC-4'),

  ('Third Party Risk', 3,
   'Is third-party remote access restricted to specific systems and monitored/logged?',
   'high',
   'Third-party remote access should use MFA and be time-limited.',
   'Security Policies §10', 'PR.AC-3'),

  ('Third Party Risk', 4,
   'Do you manage a register of all third parties with access to your systems or data?',
   'medium',
   'Vendor inventory is the foundation of third-party risk management.',
   'Third Party §1', 'ID.SC-1'),

  -- ── Security Governance & Awareness ───────────────────────────────────────
  ('Security Governance & Awareness', 1,
   'Do you have documented information security policies reviewed at least annually?',
   'high',
   'Policies must be current and communicated to all staff.',
   'Security Policies §4', 'GV.PO-1'),

  ('Security Governance & Awareness', 2,
   'Do you have a dedicated person responsible for information security (CISO, IT Security Manager)?',
   'medium',
   'Even a part-time security champion is better than no accountability.',
   'Security Policies §2', 'GV.RR-2'),

  ('Security Governance & Awareness', 3,
   'Have all employees completed security awareness training in the past 12 months?',
   'high',
   'Annual training is a minimum. Quarterly refreshers with phishing simulations are best practice.',
   'Personnel Security §2', 'PR.AT-1'),

  ('Security Governance & Awareness', 4,
   'Do you run phishing simulation campaigns to test employee awareness?',
   'medium',
   'Phishing simulations should be run at least quarterly with remedial training for those who click.',
   'Personnel Security §3', 'PR.AT-1'),

  ('Security Governance & Awareness', 5,
   'Do you have network segmentation to isolate critical systems and sensitive data?',
   'high',
   'Flat networks allow ransomware to spread rapidly. DMZ and VLAN segmentation limit blast radius.',
   'Security Implementation §2', 'PR.AC-5'),

  ('Security Governance & Awareness', 6,
   'Do you have a formal change management process covering risk assessment, testing, and rollback?',
   'medium',
   'Change management prevents accidental security misconfigurations.',
   'Change Management §1', 'PR.IP-3')

) AS q(section, order_num, text, weight, help_text, itoo_ref, nist_ref)
WHERE NOT EXISTS (SELECT 1 FROM grc_questions LIMIT 1);
