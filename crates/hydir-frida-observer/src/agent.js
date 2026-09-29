// Runs only in the staged target. Rust owns identity checks and artifact validation.
const moduleBase = Process.mainModule.base;
const moduleEnd = moduleBase.add(Process.mainModule.size);
const selected = moduleBase.add(__OFFSET__);
const cap = __CAP__;
let count = 0;
let lost = 0;
let activeRun = null;
let finished = false;
let nextInvocationId = 1;
const jumpEvidence = [];

function record(value) {
  send({ type: 'hydir', id: 0, result: 'event', returns: value });
}

function emit(payload, threadId) {
  emitBatch([payload], threadId);
}
function emitBatch(payloads, threadId) {
  const accepted = [];
  for (const payload of payloads) {
    if (count >= cap) { lost++; continue; }
    payload.thread_id = threadId;
    accepted.push(payload);
    count++;
  }
  if (accepted.length !== 0)
    record({ type: 'batch', events: accepted });
}
function witness(address) {
  const p = ptr(address);
  let bytes = null;
  try {
    const raw = new Uint8Array(p.readByteArray(8));
    bytes = Array.from(raw, b => b.toString(16).padStart(2, '0')).join('');
  } catch (_) {}
  return { address: p.toString(), bytes: bytes };
}
function jumpWitness(address) {
  return ptr(address).equals(selected) ? selectedWitness : witness(address);
}
function entryRegisters(context) {
  const registers = { RIP: context.pc.toString(), RSP: context.sp.toString() };
  for (const name of ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp',
                      'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']) {
    if (context[name] !== undefined)
      registers[name.toUpperCase()] = context[name].toString();
  }
  return registers;
}
function inMainModule(address) {
  const value = ptr(address);
  return value.compare(moduleBase) >= 0 && value.compare(moduleEnd) < 0;
}
function sameRun(run) {
  return activeRun === run && Process.getCurrentThreadId() === run.threadId;
}
function blockEntry(run, address) {
  if (!sameRun(run)) { lost++; return; }
  const source = run.pending;
  run.pending = null;
  if (source === null || !inMainModule(address)) return;
  const target = jumpWitness(address);
  if (target.bytes === null) { lost++; return; }
  if (count >= cap) { lost++; return; }
  jumpEvidence.push({ sequence: jumpEvidence.length, thread_id: run.threadId,
                      invocation_id: run.id, source: source, target: target });
  count++;
}
function jumpSource(run, address) {
  if (!sameRun(run)) { lost++; return; }
  if (run.pending !== null) lost++;
  const source = jumpWitness(address);
  if (source.bytes === null) { lost++; run.pending = null; return; }
  run.pending = source;
}
// Interceptor replaces the entry bytes; attest them before installing it.
const selectedWitness = witness(selected);
record({ type: 'meta', base: moduleBase.toString() });
const listener = Interceptor.attach(selected, {
  onEnter() {
    this.ownedRun = null;
    if (finished) return;
    if (activeRun !== null) {
      // Recursion remains inside the one followed thread. A second thread is
      // not part of this selected invocation and makes its evidence incomplete.
      if (activeRun.threadId !== this.threadId) lost++;
      return;
    }
    const run = { id: nextInvocationId++, threadId: this.threadId, pending: null };
    this.ownedRun = run;
    activeRun = run;
    emit({ kind: 'entry', source: selectedWitness, target: null,
           registers: entryRegisters(this.context) }, run.threadId);
    Stalker.follow(run.threadId, {
      events: { call: true, ret: false, block: true, exec: false, compile: false },
      transform(iterator) {
        let instruction = iterator.next();
        let first = true;
        while (instruction !== null) {
          const address = instruction.address.toString();
          if (first) {
            iterator.putCallout(() => blockEntry(run, address));
            first = false;
          }
          if (inMainModule(address) && instruction.mnemonic === 'jmp' &&
              instruction.operands.length === 1 &&
              (instruction.operands[0].type === 'reg' ||
               instruction.operands[0].type === 'mem')) {
            iterator.putCallout(() => jumpSource(run, address));
          }
          iterator.keep();
          instruction = iterator.next();
        }
      },
      onReceive(raw) {
        const batch = [];
        for (const event of Stalker.parse(raw, { annotate: true, stringify: true })) {
          if (event[0] === 'block') {
            batch.push({ kind: 'block', source: witness(event[1]), target: null });
          } else if (event[0] === 'call') {
            batch.push({ kind: 'call', source: witness(event[1]), target: witness(event[2]) });
          }
        }
        emitBatch(batch, run.threadId);
      }
    });
  },
  onLeave() {
    const run = this.ownedRun;
    if (run === null) return;
    Stalker.unfollow(run.threadId);
    Stalker.flush();
    if (run.pending !== null) { lost++; run.pending = null; }
    emit({ kind: 'exit', source: selectedWitness, target: null }, run.threadId);
    for (let index = 0; index < jumpEvidence.length; index += 128)
      record({ type: 'jump_batch', jumps: jumpEvidence.slice(index, index + 128) });
    record({ type: 'done', lost: lost });
    activeRun = null;
    finished = true;
    listener.detach();
  }
});
