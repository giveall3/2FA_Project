// Handles logout and game token generation
// Runs on pages that include these features

// --- LOGOUT ---
// Submit the logout form via POST, then always redirect home
document.addEventListener('submit', async (e) => {
  const f = e.target;
  if (f && f.id === 'logout-form') {
    e.preventDefault();
    try {
      await fetch(f.action, { method: 'POST' }); // call /api/session/logout
    } finally {
      location.href = '/'; // go back to homepage
    }
  }
});

// --- GAME TOKEN + COPY ---
document.addEventListener('click', async (e) => {
  // Generate a short-lived game token
  if (e.target && e.target.id === 'gen-game-token') {
    e.preventDefault();
    const out = document.getElementById('game-token');           // input where token appears
    const status = document.getElementById('game-token-status'); // small status text

    if (status) status.textContent = 'Generating token...';
    try {
      const res = await fetch('/account/game-token', { method: 'POST' });
      const data = await res.json().catch(() => ({}));

      if (res.ok && data.ok) {
        if (out) out.value = data.token;
        if (status) status.textContent = 'Copy the token and paste it in the game.';
      } else {
        if (status) status.textContent = 'Error: ' + (data.error || res.status);
      }
    } catch (err) {
      if (status) status.textContent = 'Network error';
    }
  }

  // Copy the token to clipboard
  if (e.target && e.target.id === 'copy-token') {
    e.preventDefault();
    const out = document.getElementById('game-token');
    if (out && out.value) {
      navigator.clipboard.writeText(out.value).then(() => {
        const status = document.getElementById('game-token-status');
        if (status) status.textContent = 'Copied to clipboard.';
      });
    }
  }
});
