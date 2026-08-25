'use strict';

/**
 * lib/brand-assets.js — the Reflex marks, in the forms a PowerPoint needs.
 *
 * public/img/reflex-logo.png is a STACKED lockup: the knot mark above the
 * "reflex" wordmark, separated by a band of fully transparent rows. The deck
 * template uses the HORIZONTAL lockup — mark to the left of the wordmark — and
 * on blue slides it uses a white version of it.
 *
 * The HTML deck gets the white version for free with `filter: brightness(0)
 * invert(1)`. PowerPoint has no equivalent, and an image is not a shape it can
 * recolour, so the white and horizontal variants have to be produced as real
 * pixels here. Everything is derived from the single source asset, so there is
 * still only one logo file to replace when the brand changes.
 *
 * Output is cached: the composition runs once per process, not once per slide.
 */

const fs = require('fs');
const path = require('path');
const { PNG } = require('pngjs');

/* Proportions of the horizontal lockup, measured off the reference deck: the
   wordmark sits a little under three-quarters of the mark's height, optically
   centred against it. */
const WORDMARK_SCALE = 0.70;
const GAP_RATIO      = 0.14;

let _cache = null;

/** Rows that are entirely transparent — the seam between mark and wordmark. */
function transparentBands(png, minRun) {
  const { width: w, height: h, data } = png;
  const bands = [];
  let inBand = false, start = 0;
  for (let y = 0; y < h; y++) {
    let sum = 0;
    for (let x = 0; x < w; x++) sum += data[(y * w + x) * 4 + 3];
    const empty = sum < w * 2;          // tolerate stray anti-aliasing
    if (empty && !inBand) { inBand = true; start = y; }
    if (!empty && inBand) {
      inBand = false;
      if (y - start >= minRun) bands.push([start, y - 1]);
    }
  }
  return bands;
}

/** Tight bounding box of non-transparent pixels within a row range. */
function bbox(png, y0, y1) {
  const { width: w, data } = png;
  let minX = w, maxX = -1, minY = y1, maxY = -1;
  for (let y = y0; y <= y1; y++) {
    for (let x = 0; x < w; x++) {
      if (data[(y * w + x) * 4 + 3] > 8) {
        if (x < minX) minX = x;
        if (x > maxX) maxX = x;
        if (y < minY) minY = y;
        if (y > maxY) maxY = y;
      }
    }
  }
  if (maxX < 0) return null;
  return { x: minX, y: minY, w: maxX - minX + 1, h: maxY - minY + 1 };
}

/**
 * Bilinear sample from a source region into a destination rect.
 * Bilinear rather than nearest-neighbour because the wordmark is fine-stroked
 * type; nearest-neighbour leaves it visibly ragged at slide scale.
 */
function drawScaled(dst, src, sBox, dx, dy, dw, dh) {
  const sw = src.width, sh = src.height;
  for (let y = 0; y < dh; y++) {
    const sy = sBox.y + (y + 0.5) * (sBox.h / dh) - 0.5;
    const y0 = Math.max(sBox.y, Math.min(sBox.y + sBox.h - 1, Math.floor(sy)));
    const y1 = Math.min(sBox.y + sBox.h - 1, y0 + 1);
    const fy = Math.max(0, Math.min(1, sy - y0));

    for (let x = 0; x < dw; x++) {
      const sx = sBox.x + (x + 0.5) * (sBox.w / dw) - 0.5;
      const x0 = Math.max(sBox.x, Math.min(sBox.x + sBox.w - 1, Math.floor(sx)));
      const x1 = Math.min(sBox.x + sBox.w - 1, x0 + 1);
      const fx = Math.max(0, Math.min(1, sx - x0));

      const di = ((dy + y) * dst.width + (dx + x)) * 4;
      if (di < 0 || di + 3 >= dst.data.length) continue;

      for (let c = 0; c < 4; c++) {
        const p00 = src.data[((y0 * sw) + x0) * 4 + c];
        const p10 = src.data[((y0 * sw) + x1) * 4 + c];
        const p01 = src.data[((y1 * sw) + x0) * 4 + c];
        const p11 = src.data[((y1 * sw) + x1) * 4 + c];
        const top = p00 + (p10 - p00) * fx;
        const bot = p01 + (p11 - p01) * fx;
        dst.data[di + c] = Math.round(top + (bot - top) * fy);
      }
    }
  }
}

/** Recolour every visible pixel, alpha untouched — the CSS filter, in pixels. */
function recolour(png, r, g, b) {
  const out = new PNG({ width: png.width, height: png.height });
  png.data.copy(out.data);
  for (let i = 0; i < out.data.length; i += 4) {
    if (out.data[i + 3] > 0) {
      out.data[i] = r; out.data[i + 1] = g; out.data[i + 2] = b;
    }
  }
  return out;
}

function whiten(png) { return recolour(png, 255, 255, 255); }

/**
 * The cover watermark, pre-blended.
 *
 * pptxgenjs 4.x exposes `transparency` on shape fills and on text, but NOT on
 * images, so a faint image cannot be asked for at render time. The watermark
 * only ever sits on one known solid colour, so the blend is baked into the
 * pixels here instead: the result is identical and needs no feature that does
 * not exist. Source alpha is preserved so the mark's edges still feather.
 */
function blendOver(bgHex, alpha) {
  const n = parseInt(String(bgHex).replace('#', ''), 16);
  const mix = c => Math.round(255 * alpha + c * (1 - alpha));
  return [mix((n >> 16) & 255), mix((n >> 8) & 255), mix(n & 255)];
}

function crop(png, box) {
  const out = new PNG({ width: box.w, height: box.h });
  for (let y = 0; y < box.h; y++) {
    const s = ((box.y + y) * png.width + box.x) * 4;
    png.data.copy(out.data, y * box.w * 4, s, s + box.w * 4);
  }
  return out;
}

function toDataUri(png) {
  return 'data:image/png;base64,' + PNG.sync.write(png).toString('base64');
}

/**
 * Build the horizontal lockup: mark on the left, wordmark optically centred to
 * its right.
 */
function composeHorizontal(src, markBox, wordBox) {
  const H = markBox.h;
  const wordH = Math.round(H * WORDMARK_SCALE);
  const wordW = Math.round(wordBox.w * (wordH / wordBox.h));
  const gap = Math.round(H * GAP_RATIO);

  const out = new PNG({ width: markBox.w + gap + wordW, height: H });
  out.data.fill(0);

  drawScaled(out, src, markBox, 0, 0, markBox.w, markBox.h);
  drawScaled(out, src, wordBox, markBox.w + gap, Math.round((H - wordH) / 2), wordW, wordH);
  return out;
}

/**
 * loadBrand — every mark the deck needs, built once.
 *
 * Returns null if the source asset is missing or unreadable: an unbranded deck
 * is a far better outcome than a failed export.
 */
function loadBrand(rootDir, opts) {
  const o = opts || {};
  const wmBg    = o.watermarkBg || '#1077C7';
  const wmAlpha = o.watermarkAlpha == null ? 0.12 : o.watermarkAlpha;
  if (_cache !== null) return _cache;
  try {
    const file = path.join(rootDir, 'public', 'img', 'reflex-logo.png');
    const src = PNG.sync.read(fs.readFileSync(file));

    // The stacked lockup's seam. If the asset is ever replaced by a horizontal
    // one there will be no band, and the whole image is treated as the mark.
    const bands = transparentBands(src, 8);
    const seam = bands.find(b => b[0] > src.height * 0.2 && b[1] < src.height * 0.9);

    const markBox = bbox(src, 0, seam ? seam[0] - 1 : src.height - 1);
    const wordBox = seam ? bbox(src, seam[1] + 1, src.height - 1) : null;
    if (!markBox) return (_cache = null);

    const horizontal = wordBox ? composeHorizontal(src, markBox, wordBox) : crop(src, markBox);
    const mark = crop(src, markBox);

    _cache = {
      logo:       toDataUri(horizontal),
      logoWhite:  toDataUri(whiten(horizontal)),
      markWhite:  toDataUri(whiten(mark)),
      // Baked against the cover blue — see blendOver().
      markWatermark: toDataUri(recolour.apply(null, [mark].concat(blendOver(wmBg, wmAlpha)))),
      logoAspect: horizontal.width / horizontal.height,
      markAspect: mark.width / mark.height,
    };
    return _cache;
  } catch (err) {
    _cache = null;
    return null;
  }
}

/** Testing hook — the cache would otherwise outlive a fixture swap. */
function resetCache() { _cache = null; }

module.exports = { loadBrand, resetCache, whiten, recolour, blendOver, bbox, transparentBands };
