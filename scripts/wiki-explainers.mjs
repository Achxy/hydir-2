const box = (x,y,label,sub) => `<rect x="120" y="${y}" width="460" height="72" class="diagram-box"/><text x="350" y="${y+28}" text-anchor="middle">${label}</text><text x="350" y="${y+53}" text-anchor="middle" class="diagram-small">${sub}</text>`;
const arrow = y => `<path d="M350 ${y} v32 m-5 -8 l5 8 5 -8" class="diagram-line"/>`;
const flow = (id,title,steps,caption) => `<figure class="technical-figure"><div class="technical-diagram" tabindex="0" aria-label="Scrollable ${title}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 ${steps.length*110}" role="img" aria-labelledby="${id}-title"><title id="${id}-title">${title}</title>${steps.map(([a,b],i)=>box(225,i*110+10,a,b)+(i<steps.length-1?arrow(i*110+82):'')).join('')}</svg></div><figcaption>${caption}</figcaption></figure>`;
export const explainers = {
  ghidra: `<section id="byte-state-explainer"><h2>How overlapping varnodes share byte state</h2><p>A varnode names an address space, byte offset, and width. The width does not allocate a separate register. When two intervals overlap in the same space, a narrow write changes the bytes visible to a wider read. HydIR's standalone prefix maps those intervals into a compact buffer.</p>
<figure class="technical-figure"><div class="technical-diagram" tabindex="0" aria-label="Scrollable register alias diagram"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 230" role="img" aria-labelledby="alias-title"><title id="alias-title">Shared bytes in overlapping register varnodes</title><text x="30" y="32">Eight-byte view, low address first</text><rect x="30" y="52" width="640" height="55" class="diagram-box"/>${Array.from({length:8},(_,i)=>`<text x="${70+i*80}" y="86" text-anchor="middle">b${i}</text>`).join('')}<rect x="30" y="125" width="320" height="55" class="diagram-highlight"/><text x="190" y="160" text-anchor="middle">Four-byte view: b0 … b3</text><text x="30" y="215" class="diagram-small">Shared bytes change; upper-byte clearing is a separate effect.</text></svg></div><figcaption>Illustrative little-endian byte layout, independent of architecture-specific register-space offsets.</figcaption></figure>
<h3>A width alone does not imply zero extension</h3><p>Starting with <code>0x1122334455667788</code>, replacing only the low four bytes with <code>0xAABBCCDD</code> leaves <code>0x11223344AABBCCDD</code>. An x86 EAX write instead zeros the upper half of RAX. The clearing must come from the instruction's P-code effects; a four-byte varnode width does not establish it.</p><pre><code>Initial bytes:        88 77 66 55 44 33 22 11
Low four-byte write:  DD CC BB AA
Shared-byte result:   DD CC BB AA 44 33 22 11
EAX with clearing:    DD CC BB AA 00 00 00 00</code></pre><p>The <code>byte_map</code> tells a caller where to seed state. The standalone prefix returns an operation count and stops at its declared boundary. The CFG module adds known-byte arrays and bounded RAM; neither interface invents an unseeded value.</p><p><a href="/articles/ghidra-pcode-explained">Explore register aliases and P-code operations interactively</a>.</p></section>`,
  'python-sdk': `<section id="known-memory-explainer"><h2>Why allocated memory can still be unknown</h2><p>An allocation declaration answers whether an address belongs to a modeled range. The seed answers whether its bytes have known values. Declaring stack memory establishes an extent; it does not fill the region with zeroes.</p>${flow('memory','Load validation before value construction',[['Requested LOAD','address and width'],['Inside modeled range?','ELF mapping or declared allocation'],['All required bytes known?','missing bytes → explicit stop'],['Assemble value','little-endian byte order']],'Conceptual load checks. An invalid range or missing byte stops the operation rather than fabricating a value.')}
<h3>Worked example: a two-byte load</h3><p>Suppose the modeled range contains <code>0x700000</code> and <code>0x700001</code>. The first byte is known as <code>0x41</code>; the second is absent. A two-byte load cannot return <code>0x0041</code>, because that would assume the missing byte is zero. Supplying <code>0x42</code> at the second address permits <code>0x4241</code>.</p><div class="memory-example"><p><strong>Illustrative known-byte mask</strong></p><pre><code>address    initial value    known
0x700000   0x41             yes
0x700001   ??               no</code></pre><button type="button" data-memory-toggle aria-pressed="false">Supply second byte 0x42</button><p><output aria-live="polite">LOAD stops: byte at 0x700001 is unknown.</output></p></div><p>This example explains the model; it does not execute an ELF. LLVM v4 includes checked process bytes and writable globals; v5 adds declared stack and heap ranges. Unknown relocations, undeclared addresses, and missing bytes remain source-linked boundaries.</p>
<h3>Calls share machine state</h3><p><code>trace_calls</code> and <code>llvm_cfg_calls</code> share registers and modeled RAM across validated caller and callee snapshots. Function and depth budgets bound collection and execution. A concrete indirect target must identify a supported loaded callee. Unknown imports and missing callees stop explicitly.</p><p>Returns are checked against their modeled targets. Inspect the operation log and stop record before interpreting an emitted module as a complete function. Its fidelity stays unknown until the relevant path is compared with an execution oracle.</p></section>`,
  service: `<section id="revision-explainer"><h2>Following an ELF through immutable revisions</h2><p>A project ID identifies a workspace; a revision identifies its requested state; a digest identifies bytes. A valid project ID alone does not establish that an artifact belongs to the binary currently shown in the UI.</p>${flow('revision','Revision-bound artifact lifecycle',[['Upload ELF B','creates immutable revision r'],['Analysis job at r','request key identifies a retry'],['Artifact response','revision r and content SHA-256'],['Client validation','revision, digest, media, schema']],'A job remains bound to its original revision even when later uploads advance the project.')}
<h3>Retries and stale writes are different</h3><p>If a client loses an idempotent request's response, retrying the same key can recover its result. A new mutation based on an old revision is a different operation. Accepting that mutation would risk applying analyst facts to changed project state, so the revision ledger rejects stale writes.</p><p>Suppose analysis starts at <code>r</code> and a later upload creates <code>r+1</code>. The earlier artifact can remain valid evidence for <code>r</code>; the client must not present it as output for <code>r+1</code>. The SDK validates the returned revision, media type, JSON schema version, and SHA-256 before exposing native artifacts.</p><h3>Event replay is delivery replay</h3><p><code>after_sequence</code> resumes reading sequenced job events. It does not rerun the ELF or restart analysis. Cancellation is a separate job operation. The service has no uploaded-program execution endpoint.</p></section>`,
  frida: `<section id="observed-target-explainer"><h2>What one observed indirect target establishes</h2><p>Static analysis may identify a computed call while leaving its destination unknown. Frida can witness one target for the selected input. HydIR checks binary and input bindings and relevant bytes before treating that witness as a candidate.</p>${flow('observation','Observation-guided recovery',[['Static computed edge','target remains unknown'],['Frida witness for one input','observed target T'],['Byte-verified candidate plan','T supplements the unknown edge'],['Isolated reanalysis','original snapshot retained']],'This shows the evidence flow, not a proof that T is the only possible destination.')}
<h3>Observed, recovered, and complete</h3><ul><li><strong>Observed:</strong> an event occurred in the recorded run.</li><li><strong>Candidate:</strong> validated evidence can guide bounded static analysis.</li><li><strong>Complete:</strong> all possible targets are accounted for. One run does not establish this.</li></ul><p>A comparison may be inconclusive because the executor stops before the event, state is missing, or a path diverges. Inconclusive does not mean matched. Inspect the Session input, Events, source addresses, and stop reasons together.</p></section>`
};

const sourceLinks = {
  ghidra: [['crates/hydir-ir/src/pcode/state.rs', 'P-code byte state'], ['crates/hydir-ir/src/pcode/seed.rs', 'Seed validation']],
  'python-sdk': [['crates/hydir-ir/src/pcode/execution.rs', 'Concrete execution'], ['crates/hydir-ir/src/pcode/interprocedural.rs', 'Call and return handling']],
  service: [['crates/hydir-api/proto/hydir_v3.proto', 'v3 revision and artifact contract']],
  frida: [['sdk/python/hydir_sdk/ghidra.py', 'Observation and rediscovery SDK']]
};
for (const [slug, links] of Object.entries(sourceLinks)) {
  explainers[slug] += '<p class="doc-source">Implementation references: ' + links.map(([file,label]) => `<a href="https://github.com/Achxy/hydir-2/blob/main/${file}">${label}</a>`).join(' · ') + '</p>';
}

explainers['native-analysis'] = `<section id="native-pipeline-explainer"><h2>The native artifact pipeline</h2><figure class="technical-figure"><div class="technical-diagram" tabindex="0" aria-label="Scrollable native pipeline"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 255" role="img" aria-labelledby="native-pipeline-title"><title id="native-pipeline-title">ELF bytes through native analysis and C views</title>${[['ELF bytes',25,20],['ProgramSpec',195,20],['FunctionIndex',365,20],['MachineIR',535,20],['StateIR',535,125],['FunctionIR',365,125],['CIR',195,125],['C views / unit',25,125]].map(([label,x,y])=>`<rect x="${x}" y="${y}" width="140" height="56" class="diagram-box"/><text x="${x+70}" y="${y+34}" text-anchor="middle">${label}</text>`).join('')}<path d="M165 48 H195 M335 48 H365 M505 48 H535 M605 76 V125 M535 153 H505 M365 153 H335 M195 153 H165" class="diagram-line"/><text x="25" y="224" class="diagram-small">FunctionIR → LLVM export. Every stage retains evidence and limits.</text></svg></div><figcaption>Conceptual stage order. Machine decoding uses the ELF bytes and function extent evidence; generated views remain independently scoped artifacts.</figcaption></figure><p>The index answers where a candidate function begins and why. MachineIR answers which instructions and edges were decoded. StateIR versions machine components across joins. FunctionIR and CIR support ABI facts and C rendering. These are different contracts, so a successful early stage does not imply success at every later stage.</p></section>`;


// Sketch diagrams keep the labels precise while the paths stay deliberately loose.
const sketchRegion = (x,y,w,h,cls='diagram-box') => `<path d="M${x+15} ${y+2} Q${x+w/2} ${y-2} ${x+w-15} ${y+1} Q${x+w+1} ${y+2} ${x+w} ${y+18} L${x+w-1} ${y+h-15} Q${x+w-1} ${y+h+2} ${x+w-16} ${y+h} Q${x+w/2} ${y+h-3} ${x+15} ${y+h+1} Q${x-2} ${y+h} ${x+1} ${y+h-16} L${x} ${y+18} Q${x} ${y} ${x+15} ${y+2} Z" class="${cls}"/>`;
const regionFlow = (id, title, steps, caption) => `<section id="${id}"><h2>${title}</h2><figure class="technical-figure"><div class="technical-diagram sketch-diagram" tabindex="0" aria-label="Scrollable ${title}"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 ${steps.length*120+44}" role="img" aria-labelledby="${id}-title"><title id="${id}-title">${title}</title>${steps.map(([label,detail],i)=>{const x=110,y=24+i*120;return `${i<steps.length-1?`<path d="M${x+346} ${y+82} C${x+340} ${y+110} ${x+346} ${y+100} ${x+346} ${y+120} m-6 -9 l6 9 5 -10" class="diagram-line"/>`:''}<text x="${x-17}" y="${y+29}" class="sketch-number">${i+1}</text>${sketchRegion(x,y,660,82,`diagram-box diagram-region-${i%3}`)}<text x="${x+20}" y="${y+32}">${label}</text><text x="${x+20}" y="${y+60}" class="diagram-small">${detail}</text>`;}).join('')}</svg></div><figcaption>${caption}</figcaption></figure></section>`;
const workflows = {
  desktop: ['desktop-workflow', 'A local project keeps evidence together', [
    ['Local ELF + SHA-256', 'Open bytes; choose a discovered function'],
    ['Managed Ghidra project', 'Analyze once; collect another function when selected'],
    ['Source-linked workspace', 'Disassembly | raw P-code | CFG | IR | C views'],
    ['Analyst facts + local persistence', 'Names and assumptions remain distinct from machine evidence']
  ], 'Conceptual desktop workflow. A local project is not uploaded unless a remote operation is requested.'],
  'first-run': ['first-run-flow', 'From setup to an inspectable artifact', [
    ['hydirctl doctor', 'Check the tools required by your chosen workflow'],
    ['Open PRISM / select a function', 'GUI or CLI starts managed Ghidra analysis'],
    ['Inspect snapshot + coverage', 'Check addresses, effects, and unsupported operations'],
    ['Choose a bounded trace or LLVM artifact', 'Supply a seed and explicit budgets when required']
  ], 'A first-run sequence. Tool availability and operation support are checked independently.'],
  models: ['model-flow', 'How evidence becomes a typed view', [
    ['ELF digest + AnalysisModel v1', 'Bind names, prototypes, objects, and types to the bytes'],
    ['DWARF / Ghidra / inference / analyst edits', 'Keep the provenance of each proposed fact'],
    ['Verify model and revision', 'Validate layout and identity before saving'],
    ['Typed CIR / C output', 'Interpret machine effects using the selected model']
  ], 'Type edits affect the analysis view; they do not modify the executable or prove a prototype correct.'],
  investigation: ['investigation-flow', 'Replay and captured-state evidence', [
    ['ELF + InputSpec + budgets', 'Bind arguments, stdin, files, and goals to one binary'],
    ['Native replay / GDB capture', 'Record one execution or a selected machine-state window'],
    ['Captured registers + memory', 'Retain known bytes and the capture location'],
    ['Bounded solving + evidence report', 'Inspect candidates, limits, and explicit stop reasons']
  ], 'Replay observes one input. Captured-state solving explores a bounded window with supplied state.'],
  'vm-exploration': ['vm-flow', 'Host and virtual-PC state stay separate', [
    ['VmProfile v1 + binary digest', 'Entry, exits, VPC storage, context, bytecode ranges'],
    ['Validate analyst-scoped facts', 'Retain provenance and declared guest effects'],
    ['Explore node (host address, VPC)', 'Same host instruction may represent different guest states'],
    ['Bounded host/VPC graph', 'Unknown targets and graph limits remain explicit']
  ], 'Experimental graph recovery. This workflow does not establish automatic devirtualization.'],
  symbolic: ['symbolic-flow', 'Symbolic inputs produce bounded candidate models', [
    ['Concrete seed + selected symbolic bytes', 'State and input scope are explicit'],
    ['Triton expressions + path conditions', 'Track supported instruction effects along a bounded path'],
    ['Solver query', 'Ask for a model satisfying the selected condition'],
    ['Candidate input + validation', 'A solver model needs a separate concrete check']
  ], 'A symbolic candidate is evidence under a model and budget, not a claim about every execution.'],
  'scalar-validation': ['scalar-flow', 'A scalar lift has separate validation gates', [
    ['Function + asserted u64(u64,u64) prototype', 'Check the declared scalar subset and boundaries'],
    ['Decoded machine effects', 'Unsupported operations stop the lift explicitly'],
    ['LLVM artifact + structural checks', 'Well-formed IR does not establish behavioral equivalence'],
    ['Fixture execution comparison', 'Compare the declared input cases and record the result']
  ], 'Passing finite comparisons covers those cases; it is not a general equivalence proof.'],
  transformation: ['transformation-flow', 'Transformation and replacement have different contracts', [
    ['Binary-bound region or LLVM artifact', 'Select the supported scope and explicit assertions'],
    ['Named pass / scalar patch / restricted rebuild', 'Choose one operation with its own input contract'],
    ['Artifact verification + report', 'Check boundaries, digests, structure, and retained evidence'],
    ['Separate behavioral validation gate', 'Structural success alone does not make a rewrite safe']
  ], 'These are alternative transformation routes, not a promise that every artifact can be patched.']
};
for (const [slug, [id,title,steps,caption]] of Object.entries(workflows)) {
  explainers[slug] = regionFlow(id,title,steps,caption) + (explainers[slug] || '');
}

// Apply the same sketch surface to the earlier memory and artifact explainers.
for (const slug of Object.keys(explainers)) {
  explainers[slug] = explainers[slug].replaceAll('class="technical-diagram"', 'class="technical-diagram sketch-diagram"').replace(/<rect x="([\d.]+)" y="([\d.]+)" width="([\d.]+)" height="([\d.]+)" class="([^"]+)"\/>/g, (_,x,y,w,h,cls) => sketchRegion(Number(x),Number(y),Number(w),Number(h),cls));
}
