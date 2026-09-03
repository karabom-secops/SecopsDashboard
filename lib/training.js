'use strict';

/**
 * lib/training.js — the training portal's logic, with no database in it.
 *
 * Everything here is a pure function of the content bank and its arguments, so
 * the rules that matter — the answer key never leaving the server, grading
 * being correct, an unanswered question never counting as right — are testable
 * without Postgres, which is just as well because there is not one.
 */

const { MODULES, LEVELS, LEVEL_LABELS, BLOCK_TYPES,
        PLAYBOOKS, INCIDENT_TYPES } = require('./training/content');
const { QUESTIONS, PASS_MARK } = require('./training/questions');

/** Response phases, in the order a response actually moves through them. */
const PHASES = ['identification', 'containment', 'eradication', 'recovery',
                'post-incident-analysis'];

const PHASE_LABELS = {
  identification:            'Identification',
  containment:               'Containment',
  eradication:               'Eradication',
  recovery:                  'Recovery',
  'post-incident-analysis':  'Post-Incident Analysis',
};

/**
 * A question with the answer key removed.
 *
 * THE ONLY FUNCTION THAT PRODUCES A QUESTION FOR THE BROWSER.
 *
 * Built by naming what goes OUT rather than deleting what must not — an
 * allowlist, so a field added to the bank later (a hint, a source link, a
 * second acceptable answer) is withheld by default rather than leaking because
 * nobody remembered to add it to a blocklist. That is the same reasoning as the
 * portal's column allowlist, and for the same reason: the failure mode of the
 * other approach is silent.
 */
function publicQuestion(q) {
  return { id: q.id, q: q.q, options: (q.options || []).slice() };
}

/** The quiz for a module, safe to send. Empty when the module has no quiz. */
function publicQuiz(moduleId) {
  return (QUESTIONS[moduleId] || []).map(publicQuestion);
}

/** How many questions a module has, without exposing them. */
function quizLength(moduleId) {
  return (QUESTIONS[moduleId] || []).length;
}

/**
 * The catalogue: every module, without lesson bodies or questions.
 *
 * Deliberately excludes `lessons` — the list view has no use for them and
 * sending every body to render six cards is wasteful.
 */
function listModules() {
  return MODULES.map(m => ({
    id: m.id,
    title: m.title,
    level: m.level,
    levelLabel: LEVEL_LABELS[m.level] || m.level,
    estimateMins: m.estimateMins,
    tags: (m.tags || []).slice(),
    summary: m.summary,
    lessonCount: (m.lessons || []).length,
    quizCount: quizLength(m.id),
  }));
}

/**
 * One module with its lessons and its quiz, answer key stripped.
 *
 * Returns null for an unknown id rather than throwing, so a stale bookmark is a
 * 404 and not a 500.
 */
function getModule(id) {
  const m = MODULES.find(x => x.id === id);
  if (!m) return null;

  return {
    id: m.id,
    title: m.title,
    level: m.level,
    levelLabel: LEVEL_LABELS[m.level] || m.level,
    estimateMins: m.estimateMins,
    tags: (m.tags || []).slice(),
    summary: m.summary,
    lessons: (m.lessons || []).map(l => ({
      id: l.id,
      title: l.title,
      body: (l.body || []).filter(isKnownBlock),
    })),
    quiz: publicQuiz(m.id),
  };
}

/** True when a block is one the renderer knows how to escape and draw. */
function isKnownBlock(block) {
  if (!block || typeof block !== 'object') return false;
  return BLOCK_TYPES.some(t => Object.prototype.hasOwnProperty.call(block, t));
}

/**
 * The playbooks, shaped for display.
 *
 * READ-ONLY, AND FROM THE LIVE SOURCE. This is the same object server.js reads
 * to seed ir_activities when an incident is opened, so what an analyst studies
 * here is what they will be handed. Nothing in this module mutates it; the
 * arrays are copied on the way out so a caller cannot either.
 */
function listPlaybooks() {
  return INCIDENT_TYPES.map(t => ({
    key: t.value,
    label: t.label,
    phases: PHASES.map(p => ({
      key: p,
      label: PHASE_LABELS[p] || p,
      tasks: ((PLAYBOOKS[t.value] || {})[p] || []).slice(),
    })).filter(p => p.tasks.length),
  }));
}

/** The tasks for one incident type and phase — what a {playbook} block draws. */
function playbookFor(typeKey) {
  // One lookup, not two. There was an INCIDENT_TYPES guard above this line
  // whose only job was to return null for an unknown key — which the find
  // below already does. A mutation campaign found it by making the guard
  // return the wrong type and observing that nothing changed: a guard that
  // cannot fail is not protecting anything, it is just somewhere for a future
  // reader to look for a rule that is not there.
  return listPlaybooks().find(p => p.key === typeKey) || null;
}

/**
 * Grade an attempt.
 *
 * @param {string} moduleId
 * @param {Object} answers   { questionId: optionIndex }
 * @returns {Object|null}    null when the module has no quiz
 *
 * RULES THAT MATTER
 *
 * - An unanswered question is WRONG, not skipped. Scoring only the answered
 *   ones would let somebody answer the single question they were sure of and
 *   score 100%.
 * - A malformed answer (a string, an out-of-range index, null) is wrong rather
 *   than an error. The input comes from a browser and being hostile to it is
 *   not the same as crashing on it.
 * - `total` is the number of questions in the BANK, never the number submitted.
 */
function gradeAttempt(moduleId, answers) {
  const bank = QUESTIONS[moduleId];
  if (!bank || !bank.length) return null;

  const given = (answers && typeof answers === 'object') ? answers : {};
  let score = 0;

  const results = bank.map((q) => {
    const raw = given[q.id];
    // Strict: `true`, '1' and 1.5 are not answers. Only an exact integer index
    // into this question's options counts as one.
    const picked = Number.isInteger(raw) && raw >= 0 && raw < q.options.length
      ? raw : null;
    const correct = picked !== null && picked === q.answer;
    if (correct) score++;

    return {
      id: q.id,
      picked,
      answer: q.answer,     // revealed only now, in the graded result
      correct,
      why: q.why,           // the explanation is where the learning happens
    };
  });

  const total = bank.length;
  return {
    moduleId,
    score,
    total,
    // Rounded for DISPLAY only. The pass decision below uses the raw ratio, so
    // a 69.5% cannot round its way over the line.
    //
    // With the current banks (two and three questions) no achievable score
    // distinguishes the two — a mutation swapping this for a rounded
    // comparison passes every test, and it is an equivalent mutant rather than
    // a hole in the suite. It stops being equivalent the moment a bank has
    // seven questions, and the failure then would be a single analyst wrongly
    // passing, which is not the kind of thing anyone goes looking for.
    pct: Math.round((score / total) * 1000) / 10,
    passed: (score / total) >= PASS_MARK,
    passMark: PASS_MARK,
    results,
  };
}

/** Is this a module id we know? Used before touching the database. */
function isModuleId(id) {
  return MODULES.some(m => m.id === id);
}

/**
 * Progress keys.
 *
 * One namespaced string rather than a pair of columns, so a lesson-level key
 * can be added later without a migration. Validated on the way in — an
 * unrecognised key is refused rather than stored, or the table quietly becomes
 * a place for anything a client sends.
 */
function progressKey(kind, id) {
  return kind + ':' + id;
}

function isValidProgressKey(key) {
  const s = String(key || '');
  const m = /^module:([a-z0-9-]+)$/.exec(s);
  if (m) return isModuleId(m[1]);

  const l = /^lesson:([a-z0-9-]+)\/([a-z0-9-]+)$/.exec(s);
  if (l) {
    const mod = MODULES.find(x => x.id === l[1]);
    return !!mod && (mod.lessons || []).some(x => x.id === l[2]);
  }
  return false;
}

const PROGRESS_STATUSES = ['started', 'completed'];

module.exports = {
  MODULES,
  LEVELS,
  LEVEL_LABELS,
  BLOCK_TYPES,
  PHASES,
  PHASE_LABELS,
  PASS_MARK,
  PROGRESS_STATUSES,
  listModules,
  getModule,
  listPlaybooks,
  playbookFor,
  publicQuiz,
  quizLength,
  gradeAttempt,
  isModuleId,
  isKnownBlock,
  progressKey,
  isValidProgressKey,
};
