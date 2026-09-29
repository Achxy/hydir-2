// Runs only in the staged target. Rust owns identity checks and artifact validation.
const moduleBase = Process.mainModule.base;
const selected = moduleBase.add(__OFFSET__);
const cap = __CAP__;
let count = 0;
let lost = 0;
let depth = 0;
let activeThread = 0;

function record(value) {
  send({ type: 'hydir', id: 0, result: 'event', returns: value });
}

function emit(payload) {
  emitBatch([payload]);
}
function emitBatch(payloads) {
  const accepted = [];
  for (const payload of payloads) {
    if (count >= cap) { lost++; continue; }
    payload.thread_id = activeThread;
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
function entryRegisters(context) {
  const registers = { RIP: context.pc.toString(), RSP: context.sp.toString() };
  for (const name of ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp',
                      'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']) {
    if (context[name] !== undefined)
      registers[name.toUpperCase()] = context[name].toString();
  }
  return registers;
}
// Interceptor replaces the entry bytes; attest them before installing it.
const selectedWitness = witness(selected);
record({ type: 'meta', base: moduleBase.toString() });
Interceptor.attach(selected, {
  onEnter() {
    if (depth++ !== 0) return;
    activeThread = this.threadId;
    emit({ kind: 'entry', source: selectedWitness, target: null,
           registers: entryRegisters(this.context) });
    Stalker.follow(activeThread, {
      events: { call: true, ret: false, block: true, exec: false, compile: false },
      onReceive(raw) {
        const batch = [];
        for (const event of Stalker.parse(raw, { annotate: true, stringify: true })) {
          if (event[0] === 'block') {
            batch.push({ kind: 'block', source: witness(event[1]), target: null });
          } else if (event[0] === 'call') {
            batch.push({ kind: 'call', source: witness(event[1]), target: witness(event[2]) });
          }
        }
        emitBatch(batch);
      }
    });
  },
  onLeave() {
    if (--depth !== 0) return;
    Stalker.unfollow(activeThread);
    Stalker.flush();
    emit({ kind: 'exit', source: selectedWitness, target: null });
    record({ type: 'done', lost: lost });
  }
});
