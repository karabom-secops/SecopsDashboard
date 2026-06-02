/* carousel.js — Lightweight carousel utility for dashboard sections */

(function () {
  'use strict';

  /**
   * Carousel — manages slide navigation, autoplay, and dot indicators
   * @param {HTMLElement} containerEl - The carousel wrapper element
   * @param {Object} options - Configuration options
   *   - autoplayInterval: ms between slides (default 5000)
   *   - shouldAutoplay: bool to start autoplay immediately (default false)
   */
  class Carousel {
    constructor(containerEl, options = {}) {
      this.containerEl = containerEl;
      this.options = { autoplayInterval: 5000, shouldAutoplay: false, ...options };

      // Find carousel elements
      this.slidesEl = containerEl.querySelector('.carousel-slides');
      this.controlsEl = containerEl.querySelector('.carousel-controls');

      if (!this.slidesEl) {
        console.warn('Carousel: slides container not found');
        return;
      }

      this.slides = Array.from(this.slidesEl.children);
      this.currentIndex = 0;
      this.autoplayInterval = null;
      this.isPlaying = false;

      this._initControls();
      this._updateSlidePosition();

      if (this.options.shouldAutoplay) {
        this.startAutoplay();
      }
    }

    /**
     * Create and attach carousel control elements (arrows, dots, play/pause)
     */
    _initControls() {
      if (!this.controlsEl || this.slides.length === 0) return;

      this.controlsEl.innerHTML = '';

      // Collect slide titles from section headings
      this.slideTitles = this.slides.map(slide => {
        const heading = slide.querySelector('.section-heading');
        return heading ? heading.textContent.trim() : '';
      });

      // Previous button
      const prevBtn = document.createElement('button');
      prevBtn.className = 'carousel-btn carousel-btn-prev';
      prevBtn.innerHTML = '&#8249;';
      prevBtn.title = 'Previous';
      prevBtn.setAttribute('aria-label', 'Previous slide');
      prevBtn.addEventListener('click', () => this.prev());
      this.controlsEl.appendChild(prevBtn);

      // Dots + slide title label
      const dotsContainer = document.createElement('div');
      dotsContainer.className = 'carousel-dots';

      this.dots = [];
      for (let i = 0; i < this.slides.length; i++) {
        const dot = document.createElement('button');
        dot.className = 'carousel-dot' + (i === 0 ? ' active' : '');
        dot.title = this.slideTitles[i] || `Slide ${i + 1}`;
        dot.setAttribute('aria-label', this.slideTitles[i] || `Slide ${i + 1}`);
        dot.addEventListener('click', () => this.goToSlide(i));
        dotsContainer.appendChild(dot);
        this.dots.push(dot);
      }
      this.controlsEl.appendChild(dotsContainer);

      // Slide title label
      const titleLabel = document.createElement('span');
      titleLabel.className = 'carousel-slide-title';
      titleLabel.textContent = this.slideTitles[0] || '';
      this.controlsEl.appendChild(titleLabel);
      this.titleLabelEl = titleLabel;

      // Next button
      const nextBtn = document.createElement('button');
      nextBtn.className = 'carousel-btn carousel-btn-next';
      nextBtn.innerHTML = '&#8250;';
      nextBtn.title = 'Next';
      nextBtn.setAttribute('aria-label', 'Next slide');
      nextBtn.addEventListener('click', () => this.next());
      this.controlsEl.appendChild(nextBtn);

      this._updatePrevNextButtons();
    }

    /**
     * Update carousel slide position based on currentIndex
     */
    _updateSlidePosition() {
      if (!this.slidesEl) return;
      const offset = this.currentIndex * 100;
      this.slidesEl.style.transform = `translateX(-${offset}%)`;
    }

    /**
     * Update dot indicators for current slide
     */
    _updateDots() {
      if (!this.dots) return;
      this.dots.forEach((dot, i) => {
        dot.classList.toggle('active', i === this.currentIndex);
      });
      if (this.titleLabelEl && this.slideTitles) {
        this.titleLabelEl.textContent = this.slideTitles[this.currentIndex] || '';
      }
    }

    /**
     * Enable/disable prev/next buttons based on slide position
     */
    _updatePrevNextButtons() {
      const btns = this.controlsEl.querySelectorAll('.carousel-btn');
      if (btns.length >= 2) {
        // Left button (prev)
        btns[0].disabled = this.currentIndex === 0;
        // Right button (next)
        btns[btns.length - 1].disabled = this.currentIndex === this.slides.length - 1;
      }
    }

    /**
     * Navigate to previous slide
     */
    prev() {
      if (this.currentIndex > 0) {
        this.currentIndex--;
        this._updateSlidePosition();
        this._updateDots();
        this._updatePrevNextButtons();
      }
    }

    /**
     * Navigate to next slide
     */
    next() {
      if (this.currentIndex < this.slides.length - 1) {
        this.currentIndex++;
        this._updateSlidePosition();
        this._updateDots();
        this._updatePrevNextButtons();
      }
    }

    /**
     * Jump to specific slide index
     */
    goToSlide(index) {
      if (index >= 0 && index < this.slides.length) {
        this.currentIndex = index;
        this._updateSlidePosition();
        this._updateDots();
        this._updatePrevNextButtons();
      }
    }

    /**
     * Start automatic slide advancement
     */
    startAutoplay() {
      if (this.isPlaying || this.slides.length <= 1) return;

      this.isPlaying = true;
      if (this.toggleBtn) {
        this.toggleBtn.classList.add('playing');
        this.toggleBtn.textContent = '⏸';
      }

      this.autoplayInterval = setInterval(() => {
        if (this.currentIndex === this.slides.length - 1) {
          // Reached end, stop or loop
          this.stopAutoplay();
        } else {
          this.next();
        }
      }, this.options.autoplayInterval);
    }

    /**
     * Stop automatic slide advancement
     */
    stopAutoplay() {
      if (this.autoplayInterval) {
        clearInterval(this.autoplayInterval);
        this.autoplayInterval = null;
      }
      this.isPlaying = false;
      if (this.toggleBtn) {
        this.toggleBtn.classList.remove('playing');
        this.toggleBtn.textContent = '▶';
      }
    }

    /**
     * Toggle autoplay on/off
     */
    toggleAutoplay() {
      if (this.isPlaying) {
        this.stopAutoplay();
      } else {
        this.startAutoplay();
      }
    }

    /**
     * Destroy carousel and clean up
     */
    destroy() {
      this.stopAutoplay();
      if (this.controlsEl) {
        this.controlsEl.innerHTML = '';
      }
    }
  }

  /**
   * Initialize carousel on an element
   * Usage: window.initCarousel(elementSelector, options)
   */
  window.initCarousel = function initCarousel(selector, options = {}) {
    const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
    if (!el) {
      console.warn('Carousel: element not found:', selector);
      return null;
    }
    return new Carousel(el, options);
  };

  /**
   * Export Carousel class for advanced usage
   */
  window.Carousel = Carousel;
})();
