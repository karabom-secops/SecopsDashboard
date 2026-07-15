-- GRC Framework Alignment Migration: adds a structured question-to-control
-- mapping table so GRC scores can be broken down per framework (NIST CSF 2.0,
-- CIS Controls v8), not just per domain/section.
-- Additive only — does not touch grc_questions.nist_ref/itoo_ref or any
-- existing assessment data. Safe to re-run (idempotent table create, but the
-- seed INSERT below assumes a clean table — see step 2).
-- Run once: psql -d secops -f migrate-grc-frameworks.sql

-- 1. Schema ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS grc_question_frameworks (
  id            SERIAL PRIMARY KEY,
  question_id   INT NOT NULL REFERENCES grc_questions(id) ON DELETE CASCADE,
  framework     VARCHAR(30) NOT NULL,   -- 'NIST_CSF' | 'CIS_V8'
  control_id    VARCHAR(30) NOT NULL,   -- e.g. 'PR.AA', '6.3'
  control_title VARCHAR(200)
);
CREATE INDEX IF NOT EXISTS idx_gqf_question  ON grc_question_frameworks(question_id);
CREATE INDEX IF NOT EXISTS idx_gqf_framework ON grc_question_frameworks(framework);

-- 2. Reseed mapping rows (idempotent — clears only this table) ─────────────
DELETE FROM grc_question_frameworks;

INSERT INTO grc_question_frameworks (question_id, framework, control_id, control_title)
SELECT q.id, m.framework, m.control_id, m.control_title
FROM (VALUES
  -- ITR-001 Governance & Strategy — IT/security strategy
  ('ITR-001','NIST_CSF','GV',      'Govern'),
  ('ITR-001','CIS_V8',  '17.1',    'Designate personnel to manage security governance/incident handling'),
  -- ITR-002 Policy management
  ('ITR-002','NIST_CSF','GV.PO',   'Policy'),
  ('ITR-002','CIS_V8',  '17.2',    'Establish and maintain contact information for reporting security incidents'),
  -- ITR-003 IT risk register
  ('ITR-003','NIST_CSF','GV.RM',   'Risk Management Strategy'),
  ('ITR-003','CIS_V8',  '17.3',    'Establish and maintain an enterprise process for reporting incidents'),
  -- ITR-004 Password policy
  ('ITR-004','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-004','CIS_V8',  '5.2',     'Use unique passwords'),
  ('ITR-004','CIS_V8',  '6.1',     'Establish an access granting process'),
  -- ITR-005 MFA
  ('ITR-005','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-005','CIS_V8',  '6.3',     'Require MFA for externally-exposed applications'),
  ('ITR-005','CIS_V8',  '6.5',     'Require MFA for administrative access'),
  -- ITR-006 Orphaned accounts
  ('ITR-006','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-006','CIS_V8',  '5.3',     'Disable dormant accounts'),
  -- ITR-007 Access reviews
  ('ITR-007','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-007','CIS_V8',  '6.1',     'Establish an access granting process'),
  ('ITR-007','CIS_V8',  '6.2',     'Establish an access revoking process'),
  -- ITR-008 Shared admin accounts
  ('ITR-008','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-008','CIS_V8',  '5.4',     'Restrict administrator privileges to dedicated administrator accounts'),
  -- ITR-009 Standing global admin / JIT
  ('ITR-009','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-009','CIS_V8',  '5.4',     'Restrict administrator privileges to dedicated administrator accounts'),
  ('ITR-009','CIS_V8',  '6.8',     'Define and maintain role-based access control'),
  -- ITR-010 Endpoint patching
  ('ITR-010','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-010','CIS_V8',  '7.3',     'Perform automated OS patch management'),
  ('ITR-010','CIS_V8',  '7.4',     'Perform automated application patch management'),
  -- ITR-011 Unsupported OS
  ('ITR-011','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-011','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-011','CIS_V8',  '2.2',     'Ensure authorized software is currently supported'),
  ('ITR-011','CIS_V8',  '4.1',     'Establish and maintain a secure configuration process'),
  -- ITR-012 Endpoint protection
  ('ITR-012','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-012','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-012','CIS_V8',  '10.1',    'Deploy and maintain anti-malware software'),
  ('ITR-012','CIS_V8',  '10.2',    'Configure automatic anti-malware signature updates'),
  -- ITR-013 BEC controls
  ('ITR-013','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-013','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-013','CIS_V8',  '9.2',     'Use DNS filtering services'),
  ('ITR-013','CIS_V8',  '6.3',     'Require MFA for externally-exposed applications'),
  -- ITR-014 Phishing filtering
  ('ITR-014','NIST_CSF','PR.AT',   'Awareness and Training'),
  ('ITR-014','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-014','CIS_V8',  '9.2',     'Use DNS filtering services'),
  ('ITR-014','CIS_V8',  '9.7',     'Deploy and maintain email server anti-malware protections'),
  -- ITR-015 External sharing controls
  ('ITR-015','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-015','CIS_V8',  '3.3',     'Configure data access control lists'),
  -- ITR-016 Security awareness
  ('ITR-016','NIST_CSF','PR.AT',   'Awareness and Training'),
  ('ITR-016','CIS_V8',  '14.1',    'Establish and maintain a security awareness program'),
  ('ITR-016','CIS_V8',  '14.9',    'Conduct role-specific security awareness and skills training'),
  -- ITR-017 Insider risk
  ('ITR-017','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-017','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-017','CIS_V8',  '6.2',     'Establish an access revoking process'),
  ('ITR-017','CIS_V8',  '8.2',     'Collect audit logs'),
  -- ITR-018 Network segmentation
  ('ITR-018','NIST_CSF','PR.IR',   'Technology Infrastructure Resilience'),
  ('ITR-018','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-018','CIS_V8',  '12.2',    'Establish and maintain a secure network architecture'),
  -- ITR-019 Firewall rule review
  ('ITR-019','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-019','CIS_V8',  '4.4',     'Implement and manage a firewall on servers'),
  ('ITR-019','CIS_V8',  '12.4',    'Establish and maintain architecture diagram(s)'),
  -- ITR-020 Remote access security
  ('ITR-020','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-020','CIS_V8',  '6.3',     'Require MFA for externally-exposed applications'),
  ('ITR-020','CIS_V8',  '12.6',    'Use secure network management and communication protocols'),
  -- ITR-021 Internet resilience
  ('ITR-021','NIST_CSF','PR.IR',   'Technology Infrastructure Resilience'),
  ('ITR-021','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  ('ITR-021','CIS_V8',  '12.1',    'Ensure network infrastructure is up-to-date'),
  -- ITR-022 DDoS protection
  ('ITR-022','NIST_CSF','PR.IR',   'Technology Infrastructure Resilience'),
  ('ITR-022','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-022','CIS_V8',  '13.1',    'Centralize security event alerting'),
  -- ITR-023 Cloud config review
  ('ITR-023','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-023','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-023','CIS_V8',  '4.1',     'Establish and maintain a secure configuration process'),
  ('ITR-023','CIS_V8',  '4.2',     'Establish and maintain a secure configuration process for network infrastructure'),
  -- ITR-024 SaaS shadow IT
  ('ITR-024','NIST_CSF','GV.SC',   'Cybersecurity Supply Chain Risk Management'),
  ('ITR-024','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-024','CIS_V8',  '2.1',     'Establish and maintain a software inventory'),
  ('ITR-024','CIS_V8',  '2.5',     'Allowlist authorized software'),
  -- ITR-025 Cloud resilience/failover
  ('ITR-025','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  ('ITR-025','CIS_V8',  '11.1',    'Establish and maintain a data recovery process'),
  -- ITR-026 Web app testing
  ('ITR-026','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-026','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-026','CIS_V8',  '16.1',    'Establish and maintain a secure application development process'),
  ('ITR-026','CIS_V8',  '16.12',   'Implement code-level security checks'),
  -- ITR-027 Change management
  ('ITR-027','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-027','CIS_V8',  '4.1',     'Establish and maintain a secure configuration process'),
  -- ITR-028 API security
  ('ITR-028','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-028','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-028','CIS_V8',  '16.10',   'Apply secure design principles in application architectures'),
  -- ITR-029 Vulnerability scanning
  ('ITR-029','NIST_CSF','ID.RA',   'Risk Assessment'),
  ('ITR-029','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-029','CIS_V8',  '7.5',     'Perform automated vulnerability scans of internal enterprise assets'),
  ('ITR-029','CIS_V8',  '7.6',     'Perform automated vulnerability scans of externally-exposed assets'),
  -- ITR-030 Critical vuln remediation SLA
  ('ITR-030','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-030','CIS_V8',  '7.3',     'Perform automated OS patch management'),
  ('ITR-030','CIS_V8',  '7.4',     'Perform automated application patch management'),
  -- ITR-031 Security logging
  ('ITR-031','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-031','CIS_V8',  '8.2',     'Collect audit logs'),
  ('ITR-031','CIS_V8',  '8.5',     'Collect detailed audit logs'),
  -- ITR-032 24/7 monitoring (SOC/MDR)
  ('ITR-032','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-032','NIST_CSF','RS.MA',   'Incident Management'),
  ('ITR-032','CIS_V8',  '13.1',    'Centralize security event alerting'),
  ('ITR-032','CIS_V8',  '17.6',    'Define mechanisms for communicating during incident response'),
  -- ITR-033 Alert tuning
  ('ITR-033','NIST_CSF','DE.CM',   'Continuous Monitoring'),
  ('ITR-033','CIS_V8',  '13.2',    'Deploy a host-based intrusion detection solution'),
  -- ITR-034 IR plan tested
  ('ITR-034','NIST_CSF','RS',      'Respond'),
  ('ITR-034','NIST_CSF','RC',      'Recover'),
  ('ITR-034','CIS_V8',  '17.3',    'Establish and maintain an enterprise process for reporting incidents'),
  ('ITR-034','CIS_V8',  '17.8',    'Conduct post-incident reviews'),
  -- ITR-035 Incident communication
  ('ITR-035','NIST_CSF','RS.CO',   'Incident Response Reporting and Communication'),
  ('ITR-035','CIS_V8',  '17.4',    'Establish and maintain an incident response process'),
  ('ITR-035','CIS_V8',  '17.5',    'Assign key roles and responsibilities'),
  -- ITR-036 Data classification
  ('ITR-036','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-036','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-036','CIS_V8',  '3.1',     'Establish and maintain a data management process'),
  ('ITR-036','CIS_V8',  '3.2',     'Establish and maintain a data inventory'),
  -- ITR-037 Encryption at rest/in transit
  ('ITR-037','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-037','CIS_V8',  '3.6',     'Encrypt data on end-user devices'),
  ('ITR-037','CIS_V8',  '3.10',    'Encrypt sensitive data in transit'),
  -- ITR-038 Backups verified
  ('ITR-038','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-038','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  ('ITR-038','CIS_V8',  '11.2',    'Perform automated backups'),
  ('ITR-038','CIS_V8',  '11.3',    'Protect recovery data'),
  -- ITR-039 DR plan tested
  ('ITR-039','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  ('ITR-039','CIS_V8',  '11.5',    'Test data recovery'),
  -- ITR-040 Business continuity plan
  ('ITR-040','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  ('ITR-040','CIS_V8',  '11.5',    'Test data recovery'),
  -- ITR-041 Vendor assessment
  ('ITR-041','NIST_CSF','GV.SC',   'Cybersecurity Supply Chain Risk Management'),
  ('ITR-041','CIS_V8',  '15.1',    'Establish and maintain an inventory of service providers'),
  ('ITR-041','CIS_V8',  '15.2',    'Establish and maintain a service provider management policy'),
  -- ITR-042 Third-party access mgmt
  ('ITR-042','NIST_CSF','PR.AA',   'Identity Management, Authentication and Access Control'),
  ('ITR-042','NIST_CSF','GV.SC',   'Cybersecurity Supply Chain Risk Management'),
  ('ITR-042','CIS_V8',  '15.3',    'Classify service providers'),
  ('ITR-042','CIS_V8',  '6.2',     'Establish an access revoking process'),
  -- ITR-043 Asset inventory
  ('ITR-043','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-043','CIS_V8',  '1.1',     'Establish and maintain a detailed enterprise asset inventory'),
  ('ITR-043','CIS_V8',  '2.1',     'Establish and maintain a software inventory'),
  -- ITR-044 Configuration drift
  ('ITR-044','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-044','CIS_V8',  '4.1',     'Establish and maintain a secure configuration process'),
  ('ITR-044','CIS_V8',  '4.2',     'Establish and maintain a secure configuration process for network infrastructure'),
  -- ITR-045 Privacy compliance (POPIA/GDPR)
  ('ITR-045','NIST_CSF','GV.OC',   'Organizational Context'),
  ('ITR-045','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-045','CIS_V8',  '3.1',     'Establish and maintain a data management process'),
  -- ITR-046 Software licensing
  ('ITR-046','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-046','CIS_V8',  '2.1',     'Establish and maintain a software inventory'),
  ('ITR-046','CIS_V8',  '2.3',     'Address unauthorized software'),
  -- ITR-047 Physical access to server rooms (no direct CIS v8 control — physical security not covered by the 18 Controls)
  ('ITR-047','NIST_CSF','PR.PS',   'Platform Security'),
  -- ITR-048 Power/cooling/environmental controls (no direct CIS v8 control)
  ('ITR-048','NIST_CSF','PR.IR',   'Technology Infrastructure Resilience'),
  ('ITR-048','NIST_CSF','RC.RP',   'Incident Recovery Plan Execution'),
  -- ITR-049 Operational documentation
  ('ITR-049','NIST_CSF','GV.RR',   'Roles, Responsibilities, and Authorities'),
  ('ITR-049','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-049','CIS_V8',  '17.1',    'Designate personnel to manage incident handling'),
  -- ITR-050 Key-person dependency (no direct CIS v8 control)
  ('ITR-050','NIST_CSF','GV.RR',   'Roles, Responsibilities, and Authorities'),
  -- ITR-051 Incident/problem management
  ('ITR-051','NIST_CSF','RS.AN',   'Incident Analysis'),
  ('ITR-051','NIST_CSF','RS.MI',   'Incident Mitigation'),
  ('ITR-051','CIS_V8',  '17.7',    'Conduct routine incident response exercises'),
  -- ITR-052 IT/security budget (no direct CIS v8 control)
  ('ITR-052','NIST_CSF','GV.RM',   'Risk Management Strategy'),
  ('ITR-052','NIST_CSF','GV.RR',   'Roles, Responsibilities, and Authorities'),
  -- ITR-053 IT project delivery (no direct CIS v8 control)
  ('ITR-053','NIST_CSF','GV.OC',   'Organizational Context'),
  ('ITR-053','NIST_CSF','GV.RR',   'Roles, Responsibilities, and Authorities'),
  -- ITR-054 Generative AI governance
  ('ITR-054','NIST_CSF','GV.PO',   'Policy'),
  ('ITR-054','NIST_CSF','PR.DS',   'Data Security'),
  ('ITR-054','CIS_V8',  '3.3',     'Configure data access control lists'),
  -- ITR-055 IoT inventory
  ('ITR-055','NIST_CSF','ID.AM',   'Asset Management'),
  ('ITR-055','NIST_CSF','PR.PS',   'Platform Security'),
  ('ITR-055','CIS_V8',  '1.1',     'Establish and maintain a detailed enterprise asset inventory'),
  ('ITR-055','CIS_V8',  '12.2',    'Establish and maintain a secure network architecture')
) AS m(external_risk_id, framework, control_id, control_title)
JOIN grc_questions q ON q.external_risk_id = m.external_risk_id;
