(() => {
  'use strict';

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
