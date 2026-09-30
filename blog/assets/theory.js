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
  if (typeof ResizeObserver !== 'undefined') {
    const resizeObserver = new ResizeObserver(showEquationOverflow);
    equationScrollers.forEach(scroller => resizeObserver.observe(scroller));
  } else {
    window.addEventListener('resize', showEquationOverflow);
  }
  document.fonts.ready.then(showEquationOverflow);
  showEquationOverflow();
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

const pcodeTest = document.querySelector('#pcode-test-lab');
if (pcodeTest) {
  const rdiInput = pcodeTest.querySelector('#pcode-rdi');
  const rsiInput = pcodeTest.querySelector('#pcode-rsi');
  const error = pcodeTest.querySelector('#pcode-test-error');
  const show = (id, value) => {
    pcodeTest.querySelector('#pcode-' + id).textContent = String(value);
  };
  const parseWord = input => {
    const raw = input.value.trim();
    if (!/^(?:0x)?[0-9a-f]{1,16}$/i.test(raw)) return null;
    return BigInt('0x' + raw.replace(/^0x/i, ''));
  };
  const update = () => {
    const rdi = parseWord(rdiInput);
    const rsi = parseWord(rsiInput);
    rdiInput.setAttribute('aria-invalid', String(rdi === null));
    rsiInput.setAttribute('aria-invalid', String(rsi === null));
    if (rdi === null || rsi === null) {
      error.textContent = 'Enter one to sixteen hexadecimal digits in each register.';
      for (const id of ['and', 'cf', 'of', 'sf', 'zf', 'pf', 'branch']) show(id, '—');
      return;
    }
    error.textContent = '';
    const result = rdi & rsi;
    let lowByte = Number(result & 0xffn);
    let setBits = 0;
    while (lowByte !== 0) {
      setBits += lowByte & 1;
      lowByte >>= 1;
    }
    const zf = Number(result === 0n);
    show('and', '0x' + result.toString(16).padStart(16, '0'));
    show('cf', 0);
    show('of', 0);
    show('sf', Number((result >> 63n) & 1n));
    show('zf', zf);
    show('pf', Number(setBits % 2 === 0));
    show('branch', zf ? 'JE takes the branch' : 'JE falls through');
  };
  [rdiInput, rsiInput].forEach(input => input.addEventListener('input', update));
  pcodeTest.querySelectorAll('[data-pcode-preset]').forEach(button => {
    button.addEventListener('click', () => {
      const [rdi, rsi] = button.dataset.pcodePreset.split(',');
      rdiInput.value = rdi;
      rsiInput.value = rsi;
      update();
    });
  });
  update();
  pcodeTest.hidden = false;
}
