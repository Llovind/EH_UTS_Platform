(() => {
  'use strict';

  const toastRegion = document.createElement('div');
  toastRegion.className = 'toast-region';
  toastRegion.setAttribute('aria-live', 'polite');
  toastRegion.setAttribute('aria-atomic', 'true');
  document.body.appendChild(toastRegion);

  function showToast(title, message, kind = 'error') {
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + kind;
    toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    const content = document.createElement('div');
    content.className = 'toast-content';
    const heading = document.createElement('strong');
    heading.textContent = title || (kind === 'error' ? 'Request failed' : 'Request complete');
    content.appendChild(heading);
    if (message) {
      const detail = document.createElement('span');
      detail.textContent = message;
      content.appendChild(detail);
    }
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.textContent = '×';
    close.addEventListener('click', () => toast.remove());
    toast.append(content, close);
    toastRegion.appendChild(toast);
    window.setTimeout(() => toast.remove(), 7000);
  }

  function feedbackFromResponse(response, text, fallbackTitle) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('html')) {
      return { title: fallbackTitle, message: text.trim() || 'The request could not be completed.' };
    }
    const parsed = new DOMParser().parseFromString(text, 'text/html');
    const source = parsed.querySelector('.flash.bad, .notice.bad, .flash.good, .notice.good, .flash.info, .notice.info');
    if (!source) return { title: fallbackTitle, message: 'The request could not be completed.' };
    const heading = source.querySelector('h1, strong');
    const items = [...source.querySelectorAll('li')].map((item) => item.textContent.trim()).filter(Boolean);
    const paragraph = source.querySelector('p');
    const message = paragraph?.textContent.trim() || items.join(' ') || source.textContent.trim();
    return { title: heading?.textContent.trim() || fallbackTitle, message, kind: source.classList.contains('good') ? 'success' : 'error' };
  }

  function clearSensitiveFields(form) {
    form.querySelectorAll('input[type="password"], input[name="activation_code"], input[name="flag"], input[name="confirmation"]').forEach((input) => {
      input.value = '';
    });
  }

  function replaceDocument(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function shouldReplaceDocument(action) {
    return /\/api\/setup\/(attacker|target)\/(token|regenerate)$/.test(action) || /\/build\/challenge\/check$/.test(action);
  }

  function shouldReloadLab(action) {
    return /\/lab-space\/\d+\/flag$/.test(action);
  }

  function setupFormHandling() {
    document.querySelectorAll('form').forEach((form) => {
      if ((form.method || 'get').toLowerCase() !== 'post') return;
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (form.dataset.submitting === 'true') return;
        form.dataset.submitting = 'true';
        form.classList.add('is-submitting');
        const submitter = event.submitter;
        const submitterAction = submitter?.getAttribute('formaction');
        const action = submitterAction ? new URL(submitterAction, document.baseURI).href : (form.action || window.location.href);
        const buttons = [...form.querySelectorAll('button[type="submit"]')];
        buttons.forEach((button) => { button.disabled = true; });
        try {
          const response = await fetch(action, {
            method: 'POST',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: { Accept: 'text/html' },
            body: new URLSearchParams(new FormData(form)),
          });
          const text = await response.text();
          if (response.redirected) {
            window.location.assign(response.url);
            return;
          }
          const feedback = feedbackFromResponse(response, text, response.status >= 500 ? 'Service unavailable' : 'Request failed');
          if (!response.ok) {
            clearSensitiveFields(form);
            showToast(feedback.title, feedback.message, 'error');
          } else if (shouldReplaceDocument(action)) {
            replaceDocument(text);
            return;
          } else if (shouldReloadLab(action)) {
            showToast(feedback.title, feedback.message, feedback.kind || 'success');
            window.setTimeout(() => window.location.reload(), 350);
            return;
          } else if (feedback.message) {
            showToast(feedback.title, feedback.message, feedback.kind || 'success');
          }
        } catch {
          clearSensitiveFields(form);
          showToast('Connection failed', 'The portal could not complete the request. Check your connection and try again.', 'error');
        } finally {
          form.dataset.submitting = 'false';
          form.classList.remove('is-submitting');
          buttons.forEach((button) => { button.disabled = false; });
        }
      });
    });
  }

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy || '');
        const original = button.textContent;
        button.textContent = 'COPIED';
        setTimeout(() => { button.textContent = original; }, 1200);
      } catch {
        button.textContent = 'COPY FAILED';
      }
    });
  });

  setupFormHandling();

  const learnStorageKey = 'mbc-las-w4-learn-progress-v1';
  function readLearnProgress() {
    try {
      const value = JSON.parse(window.localStorage.getItem(learnStorageKey) || '[]');
      return new Set(Array.isArray(value) ? value.filter((item) => typeof item === 'string') : []);
    } catch {
      return new Set();
    }
  }
  function writeLearnProgress(progress) {
    try { window.localStorage.setItem(learnStorageKey, JSON.stringify([...progress])); } catch {}
  }
  function setupLearnExperience() {
    const progress = readLearnProgress();
    document.querySelectorAll('[data-module-card]').forEach((card) => {
      const complete = progress.has(card.dataset.moduleCard || '');
      card.classList.toggle('is-complete', complete);
      const label = card.querySelector('[data-module-completion]');
      if (label) label.textContent = complete ? 'COMPLETED' : 'NOT STARTED';
    });

    const moduleRoot = document.querySelector('[data-learn-module]');
    if (!moduleRoot) return;
    const moduleId = moduleRoot.dataset.learnModule || '';
    const checkpoint = document.querySelector('.learn-checkpoint');
    const completeButton = document.querySelector('[data-mark-complete]');
    const completeStatus = document.querySelector('[data-complete-status]');
    function paintCompleteState() {
      const complete = progress.has(moduleId);
      checkpoint?.classList.toggle('is-complete', complete);
      if (completeButton) completeButton.textContent = complete ? 'MODULE COMPLETED' : 'MARK MODULE COMPLETE';
      if (completeStatus) completeStatus.textContent = complete ? 'Module ini sudah ditandai selesai pada browser ini.' : 'Progress disimpan pada browser ini.';
    }
    paintCompleteState();
    completeButton?.addEventListener('click', () => {
      progress.add(moduleId);
      writeLearnProgress(progress);
      paintCompleteState();
      showToast('Module completed', 'Progress belajar tersimpan pada browser ini.', 'success');
    });

    const progressBar = document.querySelector('[data-reading-progress]');
    function updateReadingProgress() {
      if (!progressBar) return;
      const article = document.querySelector('.learn-article');
      if (!article) return;
      const top = article.getBoundingClientRect().top + window.scrollY;
      const distance = Math.max(1, article.offsetHeight - window.innerHeight);
      const amount = Math.min(1, Math.max(0, (window.scrollY - top) / distance));
      progressBar.style.width = Math.round(amount * 100) + '%';
    }
    updateReadingProgress();
    window.addEventListener('scroll', updateReadingProgress, { passive: true });
    window.addEventListener('resize', updateReadingProgress);

    const links = new Map([...document.querySelectorAll('[data-toc-link]')].map((link) => [link.dataset.tocLink, link]));
    if ('IntersectionObserver' in window && links.size) {
      const observer = new IntersectionObserver((entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top)[0];
        if (!visible) return;
        links.forEach((link) => link.classList.toggle('is-active', link.dataset.tocLink === visible.target.id));
      }, { rootMargin: '-18% 0px -68% 0px', threshold: 0 });
      document.querySelectorAll('[data-learn-section]').forEach((section) => observer.observe(section));
    }
  }

  setupLearnExperience();

  const statusNode = document.querySelector('[data-setup-status]');
  if (!statusNode) return;
  const peerType = statusNode.dataset.peerType;
  const valueNode = statusNode.querySelector('[data-status-value]');
  const ipNode = statusNode.querySelector('[data-status-ip]');
  const verifiedNode = statusNode.querySelector('[data-status-verified]');

  async function refreshStatus() {
    try {
      const response = await fetch('/api/setup/status', {
        credentials: 'same-origin',
        cache: 'no-store',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) return;
      const payload = await response.json();
      const peer = payload[peerType];
      if (!peer) return;
      if (valueNode) valueNode.textContent = String(peer.status || 'not_started').replaceAll('_', ' ').toUpperCase();
      if (ipNode) ipNode.textContent = peer.ip || 'NOT ASSIGNED';
      if (verifiedNode) verifiedNode.textContent = peer.lastVerifiedAt || 'NOT VERIFIED';
      statusNode.dataset.status = peer.status || 'not_started';
    } catch {
      // A transient polling failure should not interrupt setup instructions.
    }
  }

  refreshStatus();
  const timer = setInterval(refreshStatus, 5000);
  window.addEventListener('pagehide', () => clearInterval(timer), { once: true });
})();
