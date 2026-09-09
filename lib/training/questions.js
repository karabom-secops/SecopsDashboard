'use strict';

/**
 * lib/training/questions.js — the knowledge checks, INCLUDING THE ANSWER KEY.
 *
 * THIS FILE MUST NEVER BE REACHABLE FROM THE BROWSER.
 *
 * public/ is served by express.static above the session middleware, so anything
 * placed there is downloadable without logging in. That is why this lives in
 * lib/, why the API strips `answer` and `why` from every module it serves, and
 * why grading happens in lib/training.js on the server rather than in the tab.
 *
 * It would have been simpler to ship the bank to the browser and grade there.
 * The cost of that shortcut is not paid on the day it is taken — it is paid the
 * first time somebody wants these scores to mean something, at which point
 * every attempt already recorded is worthless and has to be discarded.
 *
 * SHAPE
 *
 *   { id, q, options: [...], answer: <index>, why: '...' }
 *
 * `answer` is an index into `options`. `why` is shown ONLY after grading — the
 * explanation is where the learning happens, so a wrong answer should teach
 * rather than just score zero.
 *
 * Questions are written to test judgement rather than recall. "Which of these
 * is a phase of NIST IR" checks whether someone read a list; "the user clicked
 * but says they did not enter credentials, what changes" checks whether they
 * understood why the distinction exists.
 */

/** Share of questions that must be right to pass. */
const PASS_MARK = 0.7;

/** moduleId -> ordered questions. A module with no entry has no quiz. */
const QUESTIONS = {
  'triage-fundamentals': [
    {
      id: 'q1',
      q: 'An alert shows 40 failed SSH logins from an external address over six ' +
         'minutes, and no successful authentication. What is the most useful ' +
         'thing to record?',
      options: [
        'The source IP and the number of attempts',
        'That no successful authentication occurred in the window',
        'The Wazuh rule id that fired',
        'The time the alert was received',
      ],
      answer: 1,
      why: 'All four are worth capturing, but the absence of a successful ' +
           'authentication is the finding that decides whether this is a closed ' +
           'nuisance or an active intrusion. Recording what you checked and ' +
           'found nothing is what stops the next analyst repeating the work.',
    },
    {
      id: 'q2',
      q: 'Triage is best described as:',
      options: [
        'Determining the root cause of an alert',
        'Deciding whether an alert needs a human now, and recording why',
        'Closing false positives so the queue stays clean',
        'Assigning a severity rating',
      ],
      answer: 1,
      why: 'Triage sorts; it does not solve. Trying to establish root cause ' +
           'during triage is the most common way to spend an hour on something ' +
           'that needed four minutes.',
    },
    {
      id: 'q3',
      q: 'You cannot determine whether the activity is still ongoing. What do ' +
         'you put in the record?',
      options: [
        'Leave that field blank and move on',
        'Mark it as no longer active, since nothing new has fired',
        'State explicitly that it could not be determined, and why',
        'Escalate immediately regardless of anything else',
      ],
      answer: 2,
      why: 'A blank field and an answered one look identical a week later. ' +
           'Saying "could not be determined — no agent on the host" is itself ' +
           'useful, and it is honest in a way that a guess is not.',
    },
  ],

  'phishing-response': [
    {
      id: 'q1',
      q: 'A user reports a phishing email. What must happen before the message ' +
         'is purged from mailboxes?',
      options: [
        'Block the sender domain at the gateway',
        'Preserve the original message with full headers, and establish the recipient list',
        'Force a password reset for the reporting user',
        'Notify the client',
      ],
      answer: 1,
      why: 'Purging destroys the headers and the evidence of who received it. ' +
           'Both are gone for good, and both are how you establish whether this ' +
           'is one message or a campaign.',
    },
    {
      id: 'q2',
      q: 'A recipient clicked the link but is confident they did not enter ' +
         'credentials. How does that change the response?',
      options: [
        'It does not — treat any click as a full account compromise',
        'It rules out compromise; no further action on that account',
        'It shifts the concern from the identity to the endpoint, but the account still warrants monitoring',
        'It means the incident can be closed once the email is purged',
      ],
      answer: 2,
      why: 'A click may have fetched a payload, which is an endpoint problem. A ' +
           'credential submission is an identity problem with a running clock. ' +
           'They are different incidents — but self-reported certainty is not ' +
           'evidence, so the account is still watched.',
    },
    {
      id: 'q3',
      q: 'The playbook contains a step that genuinely does not apply to this ' +
         'incident. What should you do?',
      options: [
        'Delete the task from the board',
        'Leave it pending — an incomplete board is honest',
        'Mark it complete so the board is tidy',
        'Record in the activity log why it does not apply, and close it out',
      ],
      answer: 3,
      why: 'Marking it complete claims work that was not done. Leaving it ' +
           'pending forever tells a reader nothing. Saying why it did not apply ' +
           'is the only version that survives someone reviewing the incident ' +
           'six months later.',
    },
    {
      id: 'q4',
      q: 'The reported email carries an attachment. What is the correct first ' +
         'move with VirusTotal?',
      options: [
        'Upload the file, so the sandbox verdict is available to the whole team',
        'Look the file\'s SHA-256 up first, and upload only with the client\'s agreement',
        'Skip VirusTotal — the mail gateway has already scanned it',
        'Upload it now, and request removal later if the client objects',
      ],
      answer: 1,
      why: 'A hash lookup discloses nothing about the client. An upload puts ' +
           'their file in front of every VirusTotal subscriber, and the last ' +
           'option describes a withdrawal that is not actually available to ' +
           'you. The gateway having scanned it is not an answer either — it ' +
           'let the message through.',
    },
    {
      id: 'q5',
      q: 'The reported link shows no login form — it drops a file instead. Do ' +
         'you still run the message trace?',
      options: [
        'No — the trace is for credential harvesting',
        'No — the reporting user is the only confirmed recipient',
        'Yes — the trace establishes who received it, whatever the link does',
        'Only once the file is confirmed malicious',
      ],
      answer: 2,
      why: 'Scoping the send is unconditional. A login screen changes what the ' +
           'recipient list means — from people who were targeted to people who ' +
           'may have handed over a password — but never whether you need it. ' +
           'Waiting for a verdict on the file just delays the same question.',
    },
  ],

  'ransomware-response': [
    {
      id: 'q1',
      q: 'A host is actively encrypting files. What is the first action?',
      options: [
        'Power the host off to stop the encryption',
        'Isolate it from the network while leaving it running',
        'Capture a full disk image before touching anything',
        'Identify the ransomware family',
      ],
      answer: 1,
      why: 'Powering off destroys memory — where the encryption key, the ' +
           'injected process and the operator tooling live. Isolation stops the ' +
           'spread and keeps the evidence. Imaging and identification come after ' +
           'the bleeding stops.',
    },
    {
      id: 'q2',
      q: 'The client asks the analyst on the call whether they should pay the ' +
         'ransom. The correct response is:',
      options: [
        'Advise against it — paying funds further attacks',
        'Advise in favour if backups are unusable',
        'Explain that it is not our decision or our advice to give, and route it to the client\'s leadership and counsel',
        'Give them the industry statistics on recovery rates and let them decide',
      ],
      answer: 2,
      why: 'Payment carries legal and sanctions exposure that is not ours to ' +
           'assess and not ours to carry. Our job is to give that decision ' +
           'accurate inputs — scope, backup integrity, whether the actor still ' +
           'has access — quickly.',
    },
    {
      id: 'q3',
      q: 'Why does the playbook place evidence preservation in containment ' +
         'rather than eradication?',
      options: [
        'Containment tasks are assigned to more senior analysts',
        'By eradication the evidence has been destroyed by the cleanup itself',
        'It makes the phase durations more even',
        'Regulators require it in that order',
      ],
      answer: 1,
      why: 'Eradication removes persistence, wipes and rebuilds. Anything not ' +
           'captured before that is gone, and the ordering in the playbook is ' +
           'the only thing preventing it.',
    },
  ],

  'evidence-and-escalation': [
    {
      id: 'q1',
      q: 'Ordered from most to least volatile, which sequence is correct?',
      options: [
        'Disk, memory, network state, archived logs',
        'Memory, network state, disk, archived logs',
        'Network state, memory, archived logs, disk',
        'Archived logs, disk, memory, network state',
      ],
      answer: 1,
      why: 'Collect what disappears fastest first. Imaging a disk before ' +
           'capturing memory usually destroys the more useful of the two.',
    },
    {
      id: 'q2',
      q: 'Which of these should be escalated immediately, without first ' +
         'confirming it?',
      options: [
        'A single endpoint with adware detected and quarantined',
        'Repeated failed logins against one user account',
        'Evidence that a domain controller is involved',
        'A vulnerability scan generating alerts across the estate',
      ],
      answer: 2,
      why: 'Identity infrastructure changes the blast radius of everything else. ' +
           'The cost of escalating early and being wrong is a colleague\'s ten ' +
           'minutes; the cost of confirming first and being right is measured ' +
           'differently.',
    },
    {
      id: 'q3',
      q: 'An incident spans the edge of a log retention window. What does that ' +
         'require?',
      options: [
        'Nothing — retention is an infrastructure concern',
        'Exporting the relevant logs before they roll off',
        'Extending retention for the whole estate',
        'Noting the limitation in the final report only',
      ],
      answer: 1,
      why: 'Retention expires quietly and without warning. Archival logs are ' +
           'the least volatile source right up until the moment they are gone.',
    },
  ],

  'reading-an-alert': [
    {
      id: 'q1',
      q: 'A behavioural rule named "Credential Dumping Detected" fires nightly ' +
         'at 02:00 on the same three servers. The most likely first explanation ' +
         'is:',
      options: [
        'A persistent attacker with a scheduled task',
        'Legitimate tooling — backup or vulnerability scanning — matching the rule condition',
        'The rule is correctly detecting a real compromise',
        'Log timestamps are in the wrong timezone',
      ],
      answer: 1,
      why: 'Backup agents, scanners and admin tooling trip most behavioural ' +
           'rules. It still needs confirming — but a rule that fires on a ' +
           'schedule is describing a schedule, and attackers rarely keep one ' +
           'that tidy.',
    },
    {
      id: 'q2',
      q: 'Which question turns triage into detection engineering?',
      options: [
        'What is the severity of this rule?',
        'Who owns the affected asset?',
        'What would this same attack look like if it did NOT trip this rule?',
        'How many times has this fired this month?',
      ],
      answer: 2,
      why: 'It finds the gap. If you can answer it you have something worth ' +
           'writing up whether or not this particular alert was real.',
    },
  ],

  'writing-for-the-client': [
    {
      id: 'q1',
      q: 'Which sentence belongs in a client-facing incident record?',
      options: [
        '"No malicious activity was found on the host."',
        '"The host had no EDR agent, so no host telemetry was available. Network logs showed no connections to known infrastructure."',
        '"EDR flagged it and we remediated."',
        '"The host is clean."',
      ],
      answer: 1,
      why: 'It is longer, less reassuring and true. It also tells the client ' +
           'something actionable — that host is not covered — which the other ' +
           'three actively conceal.',
    },
    {
      id: 'q2',
      q: '"Consistent with" and "confirmed" are:',
      options: [
        'Interchangeable, and "confirmed" reads better',
        'Different claims that a client will act on differently',
        'Both too technical for a board audience',
        'Equivalent once the incident is closed',
      ],
      answer: 1,
      why: 'One is a hypothesis and the other is a finding. Clients spend money ' +
           'and notify regulators on the strength of that difference, so ' +
           'borrowing certainty you do not have is not a stylistic choice.',
    },
    {
      id: 'q3',
      q: 'Why does the Secure Score distinguish an unmeasured control from a ' +
         'failed one?',
      options: [
        'To make the composite score higher',
        'Because a zero from a missing upload and an earned zero mean opposite things',
        'Because regulators require the distinction',
        'To reduce the number of recommendations shown',
      ],
      answer: 1,
      why: 'The same principle as the incident record. "We did not look" and ' +
           '"we looked and it is bad" lead a client to opposite decisions, and a ' +
           'report that renders them identically is misleading even when every ' +
           'number in it is correct.',
    },
  ],
};

module.exports = { QUESTIONS, PASS_MARK };
