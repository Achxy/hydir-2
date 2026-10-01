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
    const descriptions = {
      all: 'Static analysis, concrete observation, and symbolic exploration establish different claims. Inspect each artifact with its inputs and limits.',
      frida: 'Frida runs one declared input through the isolated Linux observer. The resulting trace witnesses that run; optional Ghidra comparison and rediscovery need validated snapshot evidence.',
      triton: 'The optional Triton bridge explores bounded x86-64 paths with supplied state and symbolic inputs. Expressions and solver candidates are separate from LLVM, native C, and concrete validation.',
      ghidra: 'Ghidra exports raw P-code and control-flow evidence from the selected ELF. Bounded traces, slices, and LLVM remain scoped to supported effects.',
      native: 'The independent native frontend builds native IR artifacts. AnalysisModel facts inform typed views; they do not change the executable.',
      seed: 'Concrete execution needs supplied register and memory values. A declared range does not initialize its bytes; unknown state produces an explicit stop.'
    };
    document.querySelectorAll('[data-diagram-route]').forEach(button => button.addEventListener('click', () => {
      const section = button.closest('section');
      const route = button.dataset.diagramRoute;
      section.querySelectorAll('[data-diagram-route]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      section.querySelectorAll('[data-path]').forEach(item => {
        const paths = item.dataset.path.split(' ');
        const active = route === 'all' || paths.includes(route) || paths.includes('shared');
        item.classList.toggle('is-dimmed', !active);
        item.classList.toggle('is-highlighted', route !== 'all' && paths.includes(route));
      });
      section.querySelector('[data-diagram-summary]').textContent = descriptions[route];
    }));
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
