'use strict';

/**
 * GRC self-assessment scoring — the one authoritative implementation.
 *
 * The same weighted maths is needed in three places: the POST handler that
 * stores a score, the GET handler that reports per-section and per-framework
 * rollups, and the report deck. Keeping it here means a domain score in the
 * board report can never disagree with the same domain on the GRC tab.
 *
 * (public/js/tab-grc.js keeps its own copy on purpose — it scores answers that
 * are still in the form and have never reached the server.)
 */

/** Weighted points per control criticality. */
const WEIGHT_POINTS = { critical: 5, high: 3, medium: 2, low: 1 };

/** Points for an unrecognised weight. 'low' is supported but never seeded. */
const DEFAULT_POINTS = 2;

/**
 * Index answers by question id.
 * Accepts both shapes in circulation: `questionId` from a POST body and
 * `question_id` straight off a grc_answers row.
 */
function toAnswerMap(answers) {
  const map = {};
  (answers || []).forEach(a => {
    if (!a) return;
    const id = a.questionId != null ? a.questionId : a.question_id;
    if (id != null) map[String(id)] = a.answer;
  });
  return map;
}

/**
 * Weighted percentage over an arbitrary subset of questions.
 *
 * 'na' and unanswered leave the denominator entirely, so a domain nobody has
 * reached yet scores null — "not assessed" — rather than zero. Reporting an
 * untouched domain as 0% would read as a total control failure.
 */
function scoreQuestionSet(questions, answerMap) {
  let possible = 0;
  let earned   = 0;

  (questions || []).forEach(q => {
    const ans = answerMap[String(q.id)];
    if (!ans || ans === 'na') return;
    const pts = WEIGHT_POINTS[q.weight] || DEFAULT_POINTS;
    possible += pts;
    if (ans === 'yes')     earned += pts;
    if (ans === 'partial') earned += pts * 0.5;
  });

  return possible > 0 ? Math.round((earned / possible) * 100) : null;
}

/**
 * Overall assessment score.
 * grc_assessments.grc_score is NOT NULL, so "nothing assessed" stores as 0.
 */
function calculateGrcScore(answers, questions) {
  const score = scoreQuestionSet(questions, toAnswerMap(answers));
  return score == null ? 0 : score;
}

/**
 * Per-framework scores, keyed by grc_question_frameworks.framework.
 * A question mapped to several controls in one framework counts once; a
 * question with no mapping is excluded from every framework.
 */
function calculateFrameworkScores(answers, questions, frameworkRows) {
  const answerMap = toAnswerMap(answers);
  const qMap = {};
  (questions || []).forEach(q => { qMap[q.id] = q; });

  const buckets = {};
  (frameworkRows || []).forEach(r => {
    if (!buckets[r.framework]) {
      buckets[r.framework] = { possible: 0, earned: 0, seen: new Set() };
    }
    const b = buckets[r.framework];
    if (b.seen.has(r.question_id)) return;
    b.seen.add(r.question_id);

    const q = qMap[r.question_id];
    if (!q) return;
    const ans = answerMap[String(q.id)];
    if (!ans || ans === 'na') return;

    const pts = WEIGHT_POINTS[q.weight] || DEFAULT_POINTS;
    b.possible += pts;
    if (ans === 'yes')     b.earned += pts;
    if (ans === 'partial') b.earned += pts * 0.5;
  });

  const scores = {};
  Object.keys(buckets).forEach(fw => {
    const { possible, earned } = buckets[fw];
    scores[fw] = possible > 0 ? Math.round((earned / possible) * 100) : null;
  });
  return scores;
}

/**
 * Per-section scores keyed by grc_questions.section.
 *
 * `score` is null when the domain has no scorable answers; `answered` counts
 * every answer including 'na', so a reader can tell "not reached" from
 * "reviewed and judged not applicable".
 */
function calculateSectionScores(answers, questions) {
  const answerMap = toAnswerMap(answers);

  const bySection = {};
  (questions || []).forEach(q => {
    const name = q.section || 'Uncategorised';
    if (!bySection[name]) bySection[name] = [];
    bySection[name].push(q);
  });

  const out = {};
  Object.keys(bySection).forEach(name => {
    const qs = bySection[name];
    out[name] = {
      score:    scoreQuestionSet(qs, answerMap),
      answered: qs.filter(q => answerMap[String(q.id)]).length,
      total:    qs.length,
    };
  });
  return out;
}

module.exports = {
  WEIGHT_POINTS,
  DEFAULT_POINTS,
  toAnswerMap,
  scoreQuestionSet,
  calculateGrcScore,
  calculateFrameworkScores,
  calculateSectionScores,
};
