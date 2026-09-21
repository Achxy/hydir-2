// Optional illustrations only. Article text and all mathematics are rendered at build time.
const equationScrollers = [...document.querySelectorAll('.equation-scroll')];
const showEquationOverflow = () => {
  for (const scroller of equationScrollers) {
    const overflow = scroller.scrollWidth > scroller.clientWidth + 1;
    const equation = scroller.closest('.equation');
    equation.classList.toggle('is-scrollable', overflow);
    equation.querySelector('.equation-hint').hidden = !overflow;
  }
};
if (equationScrollers.length) {
  const resizeObserver = new ResizeObserver(showEquationOverflow);
  equationScrollers.forEach(scroller => resizeObserver.observe(scroller));
  document.fonts.ready.then(showEquationOverflow);
}

const flags = document.querySelector('#flags-lab');
if (flags) {
  const aInput = document.querySelector('#flag-a');
  const bInput = document.querySelector('#flag-b');
  const operation = document.querySelector('#flag-op');
  const signed = value => value < 128 ? value : value - 256;
  const show = (id, text) => { document.getElementById(id).textContent = text; };
  const update = () => {
    if (!aInput.checkValidity() || !bInput.checkValidity() || aInput.value === '' || bInput.value === '') {
      show('flag-bits', '—');
      show('flag-interpretation', 'Enter whole numbers from 0 to 255.');
      for (const flag of ['cf', 'of', 'zf', 'sf']) show('flag-' + flag, '—');
      show('flag-explanation', 'Both operands must be valid eight-bit unsigned values.');
      return;
    }
    const a = Number(aInput.value);
    const b = Number(bInput.value);
    const add = operation.value === 'add';
    const wide = add ? a + b : a - b;
    const result = ((wide % 256) + 256) % 256;
    const aSign = a >> 7;
    const bSign = b >> 7;
    const rSign = result >> 7;
    const carry = add ? Number(result < a) : Number(a < b);
    const overflow = Number((add ? aSign === bSign : aSign !== bSign) && aSign !== rSign);
    const signedWide = add ? signed(a) + signed(b) : signed(a) - signed(b);
    const symbol = add ? '+' : '−';
    show('flag-bits', result.toString(2).padStart(8, '0'));
    show('flag-interpretation', 'Unsigned ' + result + ' · Signed ' + signed(result));
    show('flag-cf', carry); show('flag-of', overflow);
    show('flag-zf', Number(result === 0)); show('flag-sf', rSign);
    show('flag-explanation', signed(a) + ' ' + symbol + ' ' + signed(b) + ' = ' + signedWide +
      (overflow ? ' is outside' : ' is inside') + ' the signed eight-bit range [−128, 127]. ' +
      (carry ? (add ? 'The unsigned sum carries.' : 'Unsigned subtraction needs a borrow.') :
        (add ? 'There is no unsigned carry.' : 'No unsigned borrow is needed.')));
  };
  [aInput, bInput, operation].forEach(input => input.addEventListener('input', update));
  document.querySelectorAll('[data-flag-preset]').forEach(button => {
    button.addEventListener('click', () => {
      const [a, b, op] = button.dataset.flagPreset.split(',');
      aInput.value = a; bInput.value = b; operation.value = op; update();
    });
  });
  update();
  flags.hidden = false;
}

const copies = document.querySelector('#copy-lab');
if (copies) {
  const modes = {
    before: ['x = 7, y = 11', 'Both original values are still available.', 'Incoming edge: (x, y) ← (y, x)'],
    sequential: ['x = 11, y = 11', 'The second assignment reads the new x. The original 7 is lost.', 'x = y;  // x becomes 11\ny = x;  // y reads 11'],
    parallel: ['x = 11, y = 7', 'Both sources are captured before either destination changes.', 't0 = y; t1 = x;\nx = t0; y = t1;']
  };
  document.querySelectorAll('[data-copy-mode]').forEach(button => {
    button.addEventListener('click', () => {
      document.querySelectorAll('[data-copy-mode]').forEach(item => {
        item.setAttribute('aria-pressed', String(item === button));
      });
      const [values, explanation, code] = modes[button.dataset.copyMode];
      document.getElementById('copy-values').textContent = values;
      document.getElementById('copy-explanation').textContent = explanation;
      document.getElementById('copy-code').textContent = code;
    });
  });
  copies.hidden = false;
}
