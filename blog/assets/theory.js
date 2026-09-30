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

const registerMap = document.querySelector('#pcode-register-map');
if (registerMap) {
  const start = 0x1122334455667788n;
  const cases = {
    initial: { value: start, written: [], cleared: [], note: 'The starting eight bytes are one RAX value.' },
    al: { value: (start & ~0xffn) | 0xaan, written: [0], cleared: [],
      note: 'AL names byte +0. The seven higher bytes keep their original values.' },
    ah: { value: (start & ~(0xffn << 8n)) | (0xbbn << 8n), written: [1], cleared: [],
      note: 'AH names byte +1. AL at +0 still contains 0x88.' },
    eax: { value: 0x12345678n, written: [0, 1, 2, 3], cleared: [4, 5, 6, 7],
      note: 'EAX names the low four bytes; this x86-64 write also clears the upper four.' }
  };
  const controls = registerMap.querySelector('#pcode-register-controls');
  const result = registerMap.querySelector('#pcode-register-result');
  const render = selected => {
    const state = cases[selected];
    registerMap.querySelectorAll('[data-register-byte]').forEach(cell => {
      const offset = Number(cell.dataset.registerByte);
      cell.textContent = Number((state.value >> BigInt(offset * 8)) & 0xffn)
        .toString(16).padStart(2, '0');
      cell.dataset.change = state.written.includes(offset) ? 'written'
        : state.cleared.includes(offset) ? 'cleared' : 'same';
    });
    result.textContent = 'RAX = 0x' + state.value.toString(16).padStart(16, '0') + '. ' + state.note;
    controls.querySelectorAll('[data-register-case]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.registerCase === selected));
    });
  };
  controls.querySelectorAll('[data-register-case]').forEach(button => {
    button.addEventListener('click', () => render(button.dataset.registerCase));
  });
  render('initial');
  controls.hidden = false;
}

const loadLab = document.querySelector('#pcode-load-lab');
if (loadLab) {
  const controls = loadLab.querySelector('#pcode-load-controls');
  const result = loadLab.querySelector('#pcode-load-result');
  const seededBytes = ['ef', 'be', 'ad', 'de', '00', '00', '00', '00'];
  const render = selected => {
    loadLab.querySelectorAll('[data-load-byte]').forEach(cell => {
      const offset = Number(cell.dataset.loadByte);
      const known = selected === 'known' || offset !== 3;
      cell.textContent = known ? seededBytes[offset] : '??';
      cell.dataset.known = String(known);
    });
    result.textContent = selected === 'known'
      ? 'The loaded value is 0x00000000deadbeef. A separate mapping check is needed before treating it as an executable return target.'
      : 'Inconclusive: ram[0x700003] is unknown, so the eight-byte value and RETURN target cannot be determined.';
    controls.querySelectorAll('[data-load-case]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.loadCase === selected));
    });
  };
  controls.querySelectorAll('[data-load-case]').forEach(button => {
    button.addEventListener('click', () => render(button.dataset.loadCase));
  });
  render('known');
  controls.hidden = false;
}

const pcodeTest = document.querySelector('#pcode-test-lab');
if (pcodeTest) {
  const rdiInput = pcodeTest.querySelector('#pcode-rdi');
  const rsiInput = pcodeTest.querySelector('#pcode-rsi');
  const error = pcodeTest.querySelector('#pcode-test-error');
  const show = (id, value) => {
    pcodeTest.querySelector('#pcode-' + id).textContent = String(value);
  };
  const operationRows = [...pcodeTest.querySelectorAll('[data-pcode-op]')];
  const stepCount = pcodeTest.querySelector('#pcode-step-count');
  const stepExplanation = pcodeTest.querySelector('#pcode-step-explanation');
  const previous = pcodeTest.querySelector('#pcode-step-prev');
  const next = pcodeTest.querySelector('#pcode-step-next');
  const reset = pcodeTest.querySelector('#pcode-step-reset');
  let step = 0;
  let values = null;
  const renderStep = () => {
    operationRows.forEach(row => {
      const index = Number(row.dataset.pcodeOp);
      row.classList.toggle('is-current', index === step);
      row.classList.toggle('is-complete', index < step);
      if (index === step) row.setAttribute('aria-current', 'step');
      else row.removeAttribute('aria-current');
    });
    previous.disabled = step === 0 || values === null;
    next.disabled = step === operationRows.length || values === null;
    reset.disabled = step === 0;
    stepCount.textContent = step === 0 ? 'Before operation 1 of 10'
      : 'Operation ' + step + ' of 10 · ' + (step < 10 ? '0x2013d6' : '0x2013d9');
    if (values === null) {
      stepExplanation.textContent = 'Enter valid hexadecimal inputs to step through the operations.';
      return;
    }
    const { result, lowByte, setBits, sf, zf, pf } = values;
    const hex64 = number => '0x' + number.toString(16).padStart(16, '0');
    const notes = [
      'Before operation 1, these flags have not yet been written by this instruction.',
      'CF becomes 0. TEST clears carry without changing either input register.',
      'OF becomes 0. Clearing overflow is another separate operation.',
      't0 becomes ' + hex64(result) + '. This is RDI AND RSI; neither register receives it.',
      'SF becomes ' + sf + '. Signed comparison with zero tests the high bit of t0.',
      'ZF becomes ' + zf + '. It records whether all 64 result bits are zero.',
      't1 becomes ' + hex64(BigInt(lowByte)) + '. The mask keeps only the low byte.',
      't2 becomes ' + setBits + '. POPCOUNT counts the one bits in that low byte.',
      't3 becomes ' + (setBits & 1) + '. Only the count’s low bit is needed.',
      'PF becomes ' + pf + '. An even count of one bits gives even parity.',
      zf ? 'JE reads ZF = 1 and branches to 0x2013e2.'
        : 'JE reads ZF = 0 and falls through to 0x2013db.'
    ];
    stepExplanation.textContent = notes[step];
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
      values = null;
      step = 0;
      renderStep();
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
    values = {
      result, lowByte: Number(result & 0xffn), setBits,
      sf: Number((result >> 63n) & 1n), zf, pf: Number(setBits % 2 === 0)
    };
    step = 0;
    renderStep();
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
  previous.addEventListener('click', () => { step--; renderStep(); });
  next.addEventListener('click', () => { step++; renderStep(); });
  reset.addEventListener('click', () => { step = 0; renderStep(); });
  update();
  pcodeTest.hidden = false;
}

const phi = document.querySelector('#pcode-phi-lab');
if (phi) {
  const controls = phi.querySelector('#pcode-phi-controls');
  const result = phi.querySelector('#pcode-phi-result');
  const render = path => {
    for (const name of ['true', 'false']) {
      const active = name === path;
      phi.querySelector('#phi-edge-' + name).classList.toggle('is-active', active);
      phi.querySelector('#phi-merge-' + name).classList.toggle('is-active', active);
      phi.querySelector('#phi-node-' + name).classList.toggle('is-active', active);
      controls.querySelector('[data-phi-path="' + name + '"]')
        .setAttribute('aria-pressed', String(active));
    }
    result.textContent = 'Arrived from the ' + path + ' block: x3 = ' +
      (path === 'true' ? '4' : '9') + '.';
  };
  controls.querySelectorAll('[data-phi-path]').forEach(button => {
    button.addEventListener('click', () => render(button.dataset.phiPath));
  });
  render('true');
  controls.hidden = false;
}
