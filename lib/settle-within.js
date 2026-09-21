'use strict';

/**
 * lib/settle-within.js — answer a request in time, whether or not the work has
 * finished.
 *
 * The rollup collectors behind Sync Now (FortiAnalyzer, Managed Identity,
 * DNSFilter) can take minutes. The reverse proxy in front of the server closes
 * a request long before that, and the operator then sees a 504 for work that is
 * still running perfectly well. So the route waits a bounded time and then
 * answers "still running" instead.
 *
 * Resolves with:
 *
 *   { result }       the work finished inside the window
 *   { pending: true } it did not; it carries on alone
 *
 * A rejection INSIDE the window is passed straight through, so fast failures —
 * an unverified ADOM, a disabled integration — reach the operator exactly as
 * before. A rejection AFTER the window has nobody awaiting it, so it is caught
 * and handed to `onLateError` rather than becoming an unhandled rejection,
 * which would take the process down.
 *
 * @param {Promise}  work
 * @param {number}   ms
 * @param {function} [onLateError]  called with the error if the work fails
 *                                  after the window has closed
 */
function settleWithin(work, ms, onLateError) {
  let timer;
  const late = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ pending: true }), ms);
  });

  return Promise.race([work.then(result => ({ result })), late])
    .then((outcome) => {
      if (outcome.pending) {
        work.catch((err) => { if (onLateError) onLateError(err); });
      }
      return outcome;
    })
    .finally(() => clearTimeout(timer));
}

module.exports = { settleWithin };
