// Runs only in the staged target. Rust owns identity checks and artifact validation.
const moduleBase = Process.mainModule.base;
const selected = moduleBase.add(__OFFSET__);
const traceFile = new File('/work/.hydir-agent-events', 'wb');
const cap = __CAP__;
let count = 0;
let lost = 0;
let depth = 0;
let activeThread = 0;

function record(value) {
  traceFile.write(JSON.stringify(value) + '\n');
  traceFile.flush();
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
record({ type: 'meta', base: moduleBase.toString() });
Interceptor.attach(selected, {
  onEnter() {
    if (depth++ !== 0) return;
    activeThread = this.threadId;
    emit({ kind: 'entry', source: witness(selected), target: null });
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
    emit({ kind: 'exit', source: witness(selected), target: null });
    record({ type: 'done', lost: lost });
  }
});
