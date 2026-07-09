/* ir-playbooks-data.js — shared incident-type playbook seed data.
   Loaded both in the browser (<script>) and in Node (server.js via require()). */
(function (root) {
  'use strict';

  const INCIDENT_TYPES = [
    { value: 'phishing',             label: 'Phishing' },
    { value: 'malware_ransomware',   label: 'Malware / Ransomware' },
    { value: 'data_breach',          label: 'Data Breach' },
    { value: 'insider_threat',       label: 'Insider Threat' },
    { value: 'ddos',                 label: 'DDoS' },
    { value: 'unauthorized_access',  label: 'Unauthorized Access' },
    { value: 'other',                label: 'Other' },
  ];

  // incident_type -> phase -> ordered list of playbook task strings
  const PLAYBOOKS = {
    phishing: {
      identification: ['Confirm the phishing report and preserve the original email/headers', 'Identify all recipients of the phishing message', 'Determine if any recipient clicked a link or submitted credentials'],
      containment: ['Block sender domain/IP and malicious URLs at email gateway', 'Force password reset for any compromised accounts', 'Quarantine/delete the phishing email from all mailboxes'],
      eradication: ['Remove any malware dropped via the phishing link', 'Revoke sessions/tokens for affected accounts'],
      recovery: ['Restore affected accounts to normal access with MFA enforced', 'Monitor affected accounts for suspicious activity'],
      'post-incident-analysis': ['Send user awareness reminder to affected department', 'Document lessons learned and update email filtering rules'],
    },
    malware_ransomware: {
      identification: ['Identify patient-zero host and infection vector', 'Determine malware/ransomware family and scope of spread'],
      containment: ['Isolate infected hosts from the network', 'Disable compromised accounts', 'Preserve volatile memory/logs for forensics'],
      eradication: ['Remove malware/persistence mechanisms from infected hosts', 'Patch the exploited vulnerability'],
      recovery: ['Restore affected systems from clean backups', 'Validate systems are clean before reconnecting to network'],
      'post-incident-analysis': ['Determine root cause and update detection rules', 'Review backup integrity and ransomware readiness'],
    },
    data_breach: {
      identification: ['Identify what data was accessed/exfiltrated and affected systems', 'Determine breach timeline and entry point'],
      containment: ['Revoke access for compromised accounts/credentials', 'Block exfiltration channel (network egress, API keys, etc.)'],
      eradication: ['Close the vulnerability that allowed access', 'Rotate all exposed credentials/secrets'],
      recovery: ['Restore affected systems and confirm integrity', 'Notify affected parties/regulators as required'],
      'post-incident-analysis': ['Complete breach notification/compliance documentation', 'Review access controls and data handling policies'],
    },
    insider_threat: {
      identification: ['Confirm the suspicious activity and identify the individual involved', 'Determine scope of data/systems accessed'],
      containment: ['Suspend the individual\'s access to systems and accounts', 'Preserve relevant logs and evidence'],
      eradication: ['Remove any unauthorized access or backdoors created', 'Coordinate with HR/Legal on next steps'],
      recovery: ['Restore normal operations and re-provision access as appropriate', 'Review affected systems for lingering changes'],
      'post-incident-analysis': ['Document findings for HR/Legal proceedings', 'Review access controls and monitoring for insider risk'],
    },
    ddos: {
      identification: ['Confirm attack traffic patterns and targeted assets', 'Estimate attack volume and duration'],
      containment: ['Engage DDoS mitigation/scrubbing service or upstream provider', 'Apply rate limiting/ACLs on affected endpoints'],
      eradication: ['Block confirmed malicious source ranges', 'Validate mitigation is filtering attack traffic effectively'],
      recovery: ['Confirm service availability restored for legitimate users', 'Monitor for renewed attack activity'],
      'post-incident-analysis': ['Review capacity/mitigation readiness', 'Document attack pattern for future detection'],
    },
    unauthorized_access: {
      identification: ['Confirm unauthorized access and identify affected accounts/systems', 'Determine how access was obtained'],
      containment: ['Disable/reset credentials for affected accounts', 'Revoke active sessions and tokens'],
      eradication: ['Close the access vector (vulnerability, leaked credential, misconfig)', 'Remove any unauthorized changes made'],
      recovery: ['Restore accounts/systems to normal access with MFA', 'Monitor for repeat access attempts'],
      'post-incident-analysis': ['Review authentication/authorization controls', 'Document lessons learned'],
    },
    other: {
      identification: ['Confirm and scope the incident'],
      containment: ['Contain the immediate impact'],
      eradication: ['Remove the root cause'],
      recovery: ['Restore normal operations'],
      'post-incident-analysis': ['Document lessons learned'],
    },
  };

  const api = { INCIDENT_TYPES, PLAYBOOKS };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.IrPlaybooks = api;
  }
})(typeof window !== 'undefined' ? window : globalThis);
