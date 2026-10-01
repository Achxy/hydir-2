(() => {
  let preference;
  try { preference = localStorage.getItem('hydir-theme'); } catch {}
  const system = matchMedia('(prefers-color-scheme: dark)');
  const apply = dark => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.textContent = dark ? 'Light mode' : 'Dark mode';
      button.setAttribute('aria-pressed', String(dark));
    });
  };
  apply(preference ? preference === 'dark' : system.matches);
  document.addEventListener('DOMContentLoaded', () => {
    apply(document.documentElement.dataset.theme === 'dark');
    document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => {
      preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem('hydir-theme', preference); } catch {}
      apply(preference === 'dark');
    }));
    document.querySelectorAll('[data-memory-toggle]').forEach(button => button.addEventListener('click', () => {
      const supplied = button.getAttribute('aria-pressed') !== 'true';
      button.setAttribute('aria-pressed', String(supplied));
      button.textContent = supplied ? 'Remove second byte' : 'Supply second byte 0x42';
      button.closest('.memory-example').querySelector('output').textContent = supplied ? 'LOAD succeeds: 0x41 + (0x42 << 8) = 0x4241.' : 'LOAD stops: byte at 0x700001 is unknown.';
    }));
  });
  system.addEventListener('change', event => { if (!preference) apply(event.matches); });
})();
