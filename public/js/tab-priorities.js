/* tab-priorities.js — renders the Priorities tab */

(function () {
  'use strict';

  let _weekData = null;
  let _activeFilter = 'all';

  const STATUS_CYCLE = { open: 'wip', wip: 'done', done: 'open' };
  const P_LEVEL_CLASS = { 1: 'p1', 2: 'p2', 3: 'p3', 4: 'p4', 5: 'p5' };

  // ── Public render function ─────────────────────────────────────────────────
  window.renderPriorities = function renderPriorities(weekData, section = '') {
    _weekData = weekData;
    const priorities = weekData.priorities || [];

    renderStatCards(priorities, section);
    renderFilterChips(priorities, section);
    renderCarousel(priorities, section);
  };

  // ── Stat cards ─────────────────────────────────────────────────────────────
  function renderStatCards(priorities, section = '') {
    const total = priorities.length;
    const open  = priorities.filter(p => p.status === 'open').length;
    const wip   = priorities.filter(p => p.status === 'wip').length;
    const done  = priorities.filter(p => p.status === 'done').length;

    const container = document.getElementById(`${section ? section + '-' : ''}priorities-stat-cards`);
    container.innerHTML = [
      statCard('Total', total, 'accent-blue'),
      statCard('Open',  open,  'accent-red'),
      statCard('In Progress', wip, 'accent-amber'),
      statCard('Done', done, 'accent-green'),
    ].join('');
  }

  // ── Filter chips ──────────────────────────────────────────────────────────
  function renderFilterChips(priorities, section = '') {
    const open = priorities.filter(p => p.status === 'open').length;
    const wip  = priorities.filter(p => p.status === 'wip').length;
    const done = priorities.filter(p => p.status === 'done').length;

    const chips = [
      { key: 'all',  label: `All (${priorities.length})` },
      { key: 'open', label: `Open (${open})` },
      { key: 'wip',  label: `WIP (${wip})` },
      { key: 'done', label: `Done (${done})` },
    ];

    const container = document.getElementById(`${section ? section + '-' : ''}priority-filters`);
    if (!container) return;
    container.innerHTML = chips.map(c =>
      `<button class="chip${_activeFilter === c.key ? ' active' : ''}" data-filter="${c.key}">${c.label}</button>`
    ).join('');

    container.querySelectorAll('.chip').forEach(btn => {
      btn.addEventListener('click', () => {
        _activeFilter = btn.dataset.filter;
        // Update chip active state
        container.querySelectorAll('.chip').forEach(b => b.classList.toggle('active', b.dataset.filter === _activeFilter));
        renderCarousel(_weekData.priorities || [], section);
      });
    });
  }

  // ── Carousel rendering ─────────────────────────────────────────────────────
  function renderCarousel(priorities, section = '') {
    const filtered = _activeFilter === 'all'
      ? priorities
      : priorities.filter(p => p.status === _activeFilter);

    const slidesContainer = document.getElementById(`${section ? section + '-' : ''}priorities-carousel-slides`);
    const controlsContainer = document.getElementById(`${section ? section + '-' : ''}priorities-carousel-controls`);
    if (!slidesContainer || !controlsContainer) return;

    slidesContainer.innerHTML = '';

    if (filtered.length === 0) {
      const slide = document.createElement('div');
      slide.className = 'carousel-slide';
      slide.innerHTML = '<p style="color:var(--muted);font-size:.87rem;padding:.5rem 0">No priorities in this filter.</p>';
      slidesContainer.appendChild(slide);
    } else {
      filtered.forEach((p, filteredIdx) => {
        const realIdx = priorities.indexOf(p);
        const slide = document.createElement('div');
        slide.className = 'carousel-slide';
        slide.appendChild(buildCard(p, realIdx, section));
        slidesContainer.appendChild(slide);
      });
    }

    // Initialize or reinitialize carousel
    if (window._prioritiesCarousel) {
      window._prioritiesCarousel.destroy();
    }
    window._prioritiesCarousel = window.initCarousel(`#${section ? section + '-' : ''}priorities-carousel`);
  }

  function buildCard(priority, realIdx, section = '') {
    const pClass   = P_LEVEL_CLASS[priority.priority] || 'p5';
    const isDone   = priority.status === 'done';
    const card     = document.createElement('div');
    card.className = `priority-card ${pClass}${isDone ? ' status-done' : ''}`;

    // Action items HTML
    const aiHtml = (priority.actionItems || []).length > 0
      ? `<ul class="action-items">${priority.actionItems.map(ai =>
          `<li><input type="checkbox"${isDone ? ' checked' : ''} tabindex="-1"> <span>${escHtml(ai)}</span></li>`
        ).join('')}</ul>`
      : '';

    card.innerHTML = `
      <div class="priority-card-header">
        <span class="p-badge ${pClass}">P${priority.priority}</span>
        <span class="priority-title">${escHtml(priority.title || '(No title)')}</span>
        <span class="status-pill ${priority.status}" data-idx="${realIdx}">${priority.status.toUpperCase()}</span>
      </div>
      ${priority.client ? `<div class="priority-client">Client: <strong>${escHtml(priority.client)}</strong></div>` : ''}
      ${priority.summary ? `<div class="priority-summary">${escHtml(priority.summary)}</div>` : ''}
      ${aiHtml}
    `;

    // Status pill click → cycle status → PATCH
    const pill = card.querySelector('.status-pill');
    pill.addEventListener('click', async () => {
      const currentStatus = _weekData.priorities[realIdx].status;
      const nextStatus    = STATUS_CYCLE[currentStatus] || 'open';

      pill.style.opacity = '0.5';
      try {
        const res = await fetch(
          `api/week/${window.currentWeekKey}/priority/${realIdx}`,
          {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: nextStatus }),
          }
        );
        const updated = await res.json();
        if (updated.error) { console.error(updated.error); return; }

        // Update local state and re-render
        window._lastWeekData = updated;
        _weekData = updated;
        renderPriorities(updated, section);
      } catch (err) {
        console.error('PATCH failed:', err);
      } finally {
        pill.style.opacity = '';
      }
    });

    return card;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function statCard(label, value, accent) {
    return `<div class="stat-card ${accent}">
      <span class="stat-label">${label}</span>
      <span class="stat-value">${value}</span>
    </div>`;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

})();
