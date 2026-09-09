'use strict';

/**
 * lib/training/content.js — the SOC analyst curriculum.
 *
 * WHY IT LIVES IN lib/ AND NOT public/
 *
 * express.static(PUBLIC) is mounted ABOVE the session middleware, so every file
 * under public/ is world-readable: an unauthenticated GET of
 * /js/ir-playbooks-data.js returns 200 today. Training content is served
 * through /api/training/*, behind requireAuth and the page gate, and the
 * question bank beside this file carries the answer key — which must never be
 * one view-source away.
 *
 * WHY BLOCKS AND NOT HTML
 *
 * There is no markdown library in this repo and no bundler. Storing lesson
 * bodies as HTML strings would mean rendering authored markup on a staff page —
 * an XSS surface bought for the sake of italics. Instead a body is a list of
 * typed blocks from a closed set, and the renderer escapes every value it puts
 * on the page. An unrecognised block is skipped, never passed through.
 *
 *   { p:       'a paragraph' }
 *   { h:       'a subheading' }
 *   { list:    ['a', 'bulleted', 'list'] }
 *   { steps:   ['an', 'ordered', 'list'] }
 *   { code:    'a preformatted block' }
 *   { callout: { tone: 'warn'|'info'|'good', text: '…' } }
 *   { playbook: 'phishing' }        <-- see below
 *
 * THE PLAYBOOK BLOCK IS THE POINT OF THIS WHOLE MODULE.
 *
 * It carries an incident-type key, not a copy of the steps. It renders from
 * public/js/ir-playbooks-data.js — the same object server.js reads to seed
 * ir_activities when a real incident is opened. An analyst reading the phishing
 * lesson sees the exact task list they will be handed at 3am, and when the
 * playbook changes the lesson changes with it.
 *
 * A training copy of those steps would have been easier and would have started
 * drifting the first time somebody improved the real one. Training that teaches
 * a procedure nobody follows is worse than no training.
 */

const { PLAYBOOKS, INCIDENT_TYPES } = require('../../public/js/ir-playbooks-data');

/** Difficulty bands, in the order they should be worked through. */
const LEVELS = ['foundation', 'practitioner', 'advanced'];

const LEVEL_LABELS = {
  foundation:   'Foundation',
  practitioner: 'Practitioner',
  advanced:     'Advanced',
};

/**
 * The curriculum.
 *
 * Six modules, written to be worth reading rather than twenty stubs to make a
 * grid look full. Each one teaches something an analyst is actually asked to do
 * here, against the tools and the data this platform holds.
 */
const MODULES = [
  // ── 1 ────────────────────────────────────────────────────────────────────
  {
    id: 'triage-fundamentals',
    title: 'Alert Triage Fundamentals',
    level: 'foundation',
    estimateMins: 20,
    tags: ['triage', 'process'],
    summary: 'What to establish before you escalate, and how to write it down ' +
             'so the next person does not start again.',
    lessons: [
      {
        id: 'what-triage-is',
        title: 'What triage is for',
        body: [
          { p: 'Triage answers one question: does this need a human right now? ' +
               'Not "is this bad" and not "what happened" — those come later, ' +
               'and trying to answer them first is the most common way an ' +
               'analyst loses an hour on an alert that needed four minutes.' },
          { p: 'You are sorting, not solving. The output of triage is a ' +
               'decision and a record, and the record matters as much as the ' +
               'decision because somebody else will pick this up.' },
          { h: 'The four things to establish' },
          { steps: [
            'What fired, and what does that detection actually look for?',
            'Which asset and which identity are involved?',
            'Is there evidence the activity succeeded, or only that it was attempted?',
            'Is it still happening?',
          ] },
          { callout: { tone: 'warn', text:
            'The third one is where most false escalations come from. A blocked ' +
            'connection and a completed one produce similar-looking alerts and ' +
            'mean entirely different things.' } },
        ],
      },
      {
        id: 'writing-it-down',
        title: 'Writing the record',
        body: [
          { p: 'Whatever you decide, the note you leave should let a colleague ' +
               'reconstruct your reasoning without asking you. Three sentences ' +
               'is usually enough.' },
          { code:
            'What fired:   Wazuh 5710 — sshd failed password, 40 attempts, 6 min\n' +
            'Asset:        web-prod-02 (10.4.1.22), external source 198.51.100.7\n' +
            'Succeeded?    No successful auth in the window. Account not locked.\n' +
            'Decision:     Closing as attempted brute force. Source added to blocklist.\n' +
            'Still live?   No further attempts in 30 min.' },
          { p: 'Note what you checked and found nothing, not just what you ' +
               'found. "No successful auth in the window" is a finding. Its ' +
               'absence from a ticket means the next analyst has to check again.' },
          { callout: { tone: 'info', text:
            'If you cannot answer "is it still happening", say so explicitly ' +
            'rather than leaving it blank. An unanswered question and an ' +
            'answered one look identical in a ticket a week later.' } },
        ],
      },
    ],
  },

  // ── 2 ────────────────────────────────────────────────────────────────────
  {
    id: 'phishing-response',
    title: 'Phishing Response',
    level: 'foundation',
    estimateMins: 35,
    tags: ['email', 'ir', 'phishing'],
    summary: 'From a reported email to a closed incident, including the part ' +
             'everyone forgets: the other recipients.',
    lessons: [
      {
        id: 'first-moves',
        title: 'The first ten minutes',
        body: [
          { p: 'Preserve before you delete. Once the message is pulled from ' +
               'mailboxes you lose the headers, and the headers are how you ' +
               'establish whether this was targeted, how it got past the ' +
               'gateway, and whether it is part of a campaign.' },
          { steps: [
            'Get the original message with full headers — forwarded copies lose them.',
            'Establish the full recipient list before purging anything.',
            'Determine whether anyone clicked, and separately, whether anyone submitted credentials.',
          ] },
          { callout: { tone: 'warn', text:
            'Clicked and submitted are different incidents. A click may have ' +
            'fetched a payload; a submission means an account is compromised ' +
            'and the clock is running on that identity.' } },
          { p: 'The reporting user is not the only recipient. They are the only ' +
               'one who told you. Scope the send before you scope the damage.' },
        ],
      },
      /*
       * THE BENCH PROCEDURE, AND WHY IT IS A LESSON RATHER THAN PLAYBOOK TASKS.
       *
       * The file header above warns that a training copy of playbook steps
       * starts drifting the moment somebody improves the real one. That warning
       * holds, and this lesson does not breach it, because it is written at a
       * different altitude from the task board:
       *
       *   the playbook   WHAT must be established and recorded. It is the
       *                  authority, it seeds a real incident, and it is not
       *                  restated anywhere below.
       *   this lesson    HOW you establish it on our tooling — which tool,
       *                  in which order, and who actions the block.
       *
       * So no step here duplicates a playbook task, and the next lesson says
       * outright how the two fit together. If the two ever disagree on
       * substance rather than altitude, the fix is to change the playbook in
       * public/js/ir-playbooks-data.js — not to edit around it here.
       */
      {
        id: 'working-the-alert',
        title: 'Working the alert: our procedure',
        body: [
          { p: 'The lesson before this one is what phishing response is for. ' +
               'This is how it is done here — on our tooling, in the order ' +
               'that keeps the evidence intact.' },
          { steps: [
            'Download the reported message as a .eml and open it in a viewer ' +
            'that does not fetch remote content. The headers travel with the ' +
            '.eml; a forwarded copy loses them.',

            'Inventory what it carries — every link, every attachment. Write ' +
            'them down before you touch any of them, including the ones that ' +
            'look harmless.',

            'Scan what you found: urlscan.io for the URLs, VirusTotal for the ' +
            'attachments. Read the redirect chain, not just the verdict — a ' +
            'clean result on a shortener says nothing about where it lands.',

            'Run a message trace for the full recipient list, then establish ' +
            'which of those recipients clicked and which submitted.',

            'Escalate to WPM T3 to block the sender and the URLs.',
          ] },
          { callout: { tone: 'warn', text:
            'Look the SHA-256 up on VirusTotal before you upload anything. A ' +
            'lookup discloses nothing about the client; an upload puts their ' +
            'file in front of every VirusTotal subscriber and cannot be ' +
            'withdrawn afterwards. Set urlscan.io scans to Unlisted for the ' +
            'same reason — phishing URLs routinely carry the target\'s address ' +
            'in the path, and a Public scan makes it searchable by anyone.' } },

          { h: 'A login screen changes what you are dealing with' },
          { p: 'Run the trace on every phishing alert, whatever the link turns ' +
               'out to do. A credential-harvesting page decides what the ' +
               'recipient list means; it does not decide whether you go and ' +
               'get it. A message that drops a payload instead still went to ' +
               'everyone it went to.' },
          { p: 'Where there is a login screen, the trace stops being a scoping ' +
               'exercise and becomes the list of people who may have given a ' +
               'password away. Each one who submitted is an identity incident ' +
               'with its own clock — hand those to containment as accounts, ' +
               'not as part of the email.' },

          { h: 'What the escalation carries' },
          { p: 'WPM T3 hold the gateway and action the block. Send the sender, ' +
               'the URLs and the scan results together, in one message. A ' +
               'block request with no evidence behind it comes back as a ' +
               'question, and that round trip costs more than the minute it ' +
               'saved you.' },
        ],
      },
      {
        id: 'the-playbook',
        title: 'The playbook you will be handed',
        body: [
          { p: 'When a phishing incident is opened on the Incident Response ' +
               'tab, these tasks are created automatically, in this order. ' +
               'This is not a summary of the playbook — it is the playbook.' },
          { playbook: 'phishing' },
          { p: 'The procedure in the previous lesson is how the identification ' +
               'tasks above actually get done. The board records what was ' +
               'established; it does not describe how you established it. They ' +
               'are not alternatives, and neither one replaces the other.' },
          { p: 'The task board is a floor, not a ceiling. Add what the incident ' +
               'needs; do not silently skip what is there. If a step does not ' +
               'apply, say why in the activity log rather than leaving it ' +
               'pending forever.' },
        ],
      },
    ],
  },

  // ── 3 ────────────────────────────────────────────────────────────────────
  {
    id: 'ransomware-response',
    title: 'Ransomware and Destructive Malware',
    level: 'practitioner',
    estimateMins: 30,
    tags: ['malware', 'ir', 'containment'],
    summary: 'Containment under time pressure, and the decisions that are not ' +
             'yours to make.',
    lessons: [
      {
        id: 'containment-first',
        title: 'Containment beats investigation',
        body: [
          { p: 'With active encryption, every minute of investigation costs ' +
               'files. Isolate first and reconstruct afterwards — the evidence ' +
               'you need survives isolation, and the files do not survive delay.' },
          { h: 'Isolate, do not power off' },
          { p: 'Pulling power destroys volatile memory, and memory is where the ' +
               'encryption key, the injected process and the operator\'s tooling ' +
               'live. Network isolation stops the spread and keeps the evidence.' },
          { callout: { tone: 'warn', text:
            'The exception is a host actively encrypting a file share it still ' +
            'has a mounted path to. Killing that reach is the priority; if ' +
            'isolation cannot be applied fast enough, say so and escalate.' } },
          { h: 'Decisions that are not yours' },
          { list: [
            'Whether to pay — never an analyst decision, and never discussed with the client by us.',
            'Whether to notify a regulator — legal and the client, on their counsel\'s advice.',
            'Whether to restore from backup or rebuild — the client\'s call, with our recommendation.',
          ] },
          { p: 'Your job is to give those decisions accurate inputs quickly: ' +
               'scope, entry vector, whether backups are intact, and whether ' +
               'the actor still has access.' },
        ],
      },
      {
        id: 'the-playbook',
        title: 'The playbook you will be handed',
        body: [
          { playbook: 'malware_ransomware' },
          { callout: { tone: 'info', text:
            'Note that "Preserve volatile memory/logs for forensics" sits in ' +
            'containment, not eradication. That ordering is deliberate — by ' +
            'eradication the evidence is gone.' } },
        ],
      },
    ],
  },

  // ── 4 ────────────────────────────────────────────────────────────────────
  {
    id: 'evidence-and-escalation',
    title: 'Evidence Handling and Escalation',
    level: 'practitioner',
    estimateMins: 20,
    tags: ['process', 'forensics', 'ir'],
    summary: 'What to keep, in what order, and when to stop and call someone.',
    lessons: [
      {
        id: 'order-of-volatility',
        title: 'Order of volatility',
        body: [
          { p: 'Collect what disappears fastest, first. This ordering is not ' +
               'academic — an analyst who images a disk before capturing memory ' +
               'has usually destroyed the more useful of the two.' },
          { steps: [
            'CPU registers and cache — effectively unrecoverable, rarely collected.',
            'Memory: running processes, network connections, injected code, keys.',
            'Network state: active sessions, ARP and routing tables.',
            'Disk: files, logs, artefacts.',
            'Remote and archival logs: SIEM, cloud audit trails, backups.',
          ] },
          { p: 'The last one lasts longest and is the one most often forgotten ' +
               'anyway, because retention windows expire quietly. If an incident ' +
               'spans a retention boundary, export before it rolls.' },
        ],
      },
      {
        id: 'when-to-escalate',
        title: 'When to stop and escalate',
        body: [
          { p: 'Escalate on any of these without waiting to confirm them:' },
          { list: [
            'Evidence of hands-on-keyboard activity rather than automation.',
            'Domain controller, identity provider or backup infrastructure involved.',
            'Confirmed data exfiltration, or staged archives you have not yet proven were sent.',
            'Anything that will require the client to notify a regulator or a customer.',
            'You have been on it long enough that a second pair of eyes is cheaper than another hour.',
          ] },
          { callout: { tone: 'good', text:
            'Escalating something that turns out to be routine costs a ' +
            'colleague ten minutes. Not escalating something that was not ' +
            'costs considerably more, and the asymmetry is the whole point.' } },
        ],
      },
    ],
  },

  // ── 5 ────────────────────────────────────────────────────────────────────
  {
    id: 'reading-an-alert',
    title: 'Reading a Detection Before You Trust It',
    level: 'practitioner',
    estimateMins: 20,
    tags: ['detection', 'wazuh', 'triage'],
    summary: 'A detection is an assertion by whoever wrote the rule. Knowing ' +
             'what it actually matches changes what the alert means.',
    lessons: [
      {
        id: 'what-the-rule-says',
        title: 'What the rule actually matches',
        body: [
          { p: 'Every alert is a rule author\'s guess about intent, applied to a ' +
               'log line. Before you act, read the rule. The gap between what a ' +
               'detection is named and what it matches is where false positives ' +
               'and missed intrusions both live.' },
          { h: 'Three questions' },
          { steps: [
            'What is the literal condition? A field match, a threshold, a sequence?',
            'What legitimate activity also satisfies it? Backup agents, vulnerability scanners and admin tooling trip most behavioural rules.',
            'What would the same attack look like if it did NOT trip this rule?',
          ] },
          { p: 'The third question is the one that turns triage into detection ' +
               'engineering. If you can answer it, you have found a gap worth ' +
               'writing up whether or not this alert was real.' },
          { callout: { tone: 'info', text:
            'A high-severity rule that fires constantly is not a high-severity ' +
            'rule; it is an unmaintained one. Say so — tuning is part of the ' +
            'service, not a favour.' } },
        ],
      },
    ],
  },

  // ── 6 ────────────────────────────────────────────────────────────────────
  {
    id: 'writing-for-the-client',
    title: 'Writing the Record a Client Will Read',
    level: 'advanced',
    estimateMins: 25,
    tags: ['reporting', 'communication'],
    summary: 'Incident notes end up in a board pack. Write them knowing that.',
    lessons: [
      {
        id: 'audience',
        title: 'Who actually reads this',
        body: [
          { p: 'Incident records surface in the client portal and in the monthly ' +
               'report. The reader may be a board member with no security ' +
               'background, deciding whether to fund next year\'s programme.' },
          { h: 'Three rules' },
          { list: [
            'Say what happened before what you did. The reader wants the event, not your workflow.',
            'Quantify exposure honestly, including when it is nil. "No evidence of data access" is a finding worth stating.',
            'Never imply certainty you do not have. "Consistent with" and "confirmed" are different claims and clients act on them differently.',
          ] },
          { callout: { tone: 'warn', text:
            'Avoid tool names as explanations. "EDR flagged it" tells the reader ' +
            'nothing about what happened to their business.' } },
        ],
      },
      {
        id: 'no-data-vs-nothing',
        title: '"No data" is not "nothing happened"',
        body: [
          { p: 'The single most damaging habit in incident writing is letting an ' +
               'absence of evidence read as evidence of absence. They are ' +
               'different, and a client will act on the difference.' },
          { code:
            'Wrong:  "No malicious activity was found on the host."\n' +
            'Right:  "The host had no EDR agent, so no host telemetry was\n' +
            '         available for the period. Network logs showed no\n' +
            '         outbound connections to known infrastructure."' },
          { p: 'The second version is longer, less reassuring, and true. It also ' +
               'tells the client something actionable: that host is not covered.' },
          { callout: { tone: 'good', text:
            'This principle runs through the whole platform. The Secure Score ' +
            'distinguishes an unmeasured control from a failed one for the same ' +
            'reason — a zero from a missing upload and a zero that was earned ' +
            'mean opposite things.' } },
        ],
      },
    ],
  },
];

/** Every valid block type. The renderer must handle exactly these. */
const BLOCK_TYPES = ['p', 'h', 'list', 'steps', 'code', 'callout', 'playbook'];

module.exports = {
  MODULES,
  LEVELS,
  LEVEL_LABELS,
  BLOCK_TYPES,
  // Re-exported so callers get the playbooks from one place and cannot end up
  // reading a stale copy. This module never mutates them.
  PLAYBOOKS,
  INCIDENT_TYPES,
};
