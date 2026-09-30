An instruction such as `test %rsi, %rdi` looks small in assembly. Underneath, it computes a bitwise result, sets several flags, and gives a later branch a condition to read. A decompiler eventually turns the sequence into something like `(a & b) != 0`. **P-code is the representation Ghidra uses between those two views.** It gives the effects of an instruction as a sequence of simpler operations over registers, memory, constants, and temporary values.

This article is a field guide to reading that representation. We will unpack varnodes, address spaces, widths, memory operations, branches, calls, and the distinction between raw and high P-code. A real x86-64 function gives us an example with actual addresses and operations. Near the end, we will see why these details matter when another tool, including HydIR, consumes Ghidra's output.

The best reference while reading is Ghidra's own [SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), [P-code operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), and [additional operation reference](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html). The manual defines the model; the operation pages settle questions that a printed line of P-code often leaves ambiguous.

<nav class="lesson-map" aria-label="Visual lessons in this article">
<strong>Learn by changing one thing at a time</strong>
<ol>
<li><a href="#pcode-register-map">Register bytes</a><span>See which storage views overlap.</span></li>
<li><a href="#pcode-test-lab">Nine raw operations</a><span>Step from inputs to flags and branch.</span></li>
<li><a href="#pcode-load-lab">Memory load</a><span>Remove one byte and watch certainty disappear.</span></li>
<li><a href="#pcode-phi-lab">SSA merge</a><span>Choose the predecessor that supplies a value.</span></li>
</ol>
</nav>

## Why Ghidra has P-code

Ghidra needs to analyze many instruction sets. The bytes for an x86-64 `TEST`, an ARM comparison, and a MIPS branch differ, but the analyses behind decompilation repeatedly ask similar questions: Which bytes of state were read? Which were written? What value reaches this comparison? Where can control flow go?

[SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) is Ghidra's processor-description language. A processor specification describes instruction decoding, assembly display, and the translation of instructions into P-code. P-code is a register-transfer language with a comparatively small operation vocabulary. It can say “copy these bytes,” “add two values of this width,” “load from this address space,” or “branch if this one-byte condition is nonzero.” An architecture supplies its register layout and instruction translations. The analyses can then work on P-code instead of learning every machine opcode separately.

That does not make P-code “portable assembly” in the sense of a complete standalone program. It describes operations over state that has to exist somewhere. A P-code emulator still needs memory bytes, register values, address-space definitions, and behavior for operations whose effects are external or deliberately abstracted. We will return to those boundaries.

<figure>
<div class="diagram">
<svg viewBox="0 0 780 500" role="img" aria-labelledby="pcode-flow-title pcode-flow-desc">
<title id="pcode-flow-title">Where raw and high P-code sit in Ghidra</title>
<desc id="pcode-flow-desc">Instruction bytes are decoded by a SLEIGH processor specification into assembly and raw P-code. The decompiler analyzes and transforms raw P-code into high P-code, then renders C-like text.</desc>
<defs><marker id="pcode-flow-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0 0 L7 3.5 L0 7" class="arrow"/></marker></defs>
<g class="nodes" stroke-width="1.2">
<rect x="135" y="20" width="510" height="64"/><rect x="135" y="116" width="510" height="64"/>
<rect x="135" y="212" width="510" height="64"/><rect x="135" y="308" width="510" height="64"/>
<rect x="135" y="404" width="510" height="64"/>
</g>
<g font-size="17" text-anchor="middle">
<text x="390" y="60">Machine instruction bytes</text>
<text x="390" y="156">SLEIGH decode and semantic translation</text>
<text x="390" y="252">Raw P-code: ordered instruction effects</text>
<text x="390" y="348">High P-code: analyzed values and control flow</text>
<text x="390" y="444">C-like decompiler output</text>
</g>
<g fill="none" class="edges" stroke-width="1.5" marker-end="url(#pcode-flow-arrow)">
<path d="M390 84 V113"/><path d="M390 180 V209"/><path d="M390 276 V305"/><path d="M390 372 V401"/>
</g>
</svg>
</div>
<figcaption>Raw P-code expresses instruction behavior. High P-code is a decompiler product with value and type analysis folded in.</figcaption>
</figure>

The split in that diagram explains a common misunderstanding. People say “Ghidra's P-code” while referring to either the operations attached directly to instructions or the later, optimized operations inside a decompiled function. They are related, but they answer different questions.

## The three ingredients: spaces, varnodes, operations

Ghidra's model begins with an **address space**: a named, indexed collection of storage units. A typical language specification has `ram` for main memory and `register` for processor registers. The SLEIGH compiler also supplies a `unique` space for temporary values and a `const` space for literal operands. A processor may define more spaces. A space has an address size and, for some architectures, an addressable unit larger than one byte. These details come from the selected language, not from the spelling of the P-code opcode. [Ghidra's SLEIGH introduction](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) lays out this model.

A **varnode** is a region within a space: `(space, offset, size)`. The size is in bytes. For example:

~~~text
(register, 0x38, 8)   eight bytes beginning at register offset 0x38
(unique,   0xd5700, 8) eight temporary bytes
(const,    0xff, 8)    the eight-byte literal value 255
(ram,      0x2013d6, 8) an eight-byte region of RAM
~~~

The `const` case is special: its offset supplies the **value** of the literal. `(const, 0xff, 8)` does not ask an emulator to read eight bytes from address `0xff`. Conversely, a `ram` varnode names storage at a RAM address; it does not automatically mean “the constant numeric value of this address.” Confusing an address with the bytes stored there is one of the fastest ways to misread a P-code listing.

Varnodes are **typeless storage**. They do not inherently say “signed integer,” “pointer,” or “C struct.” The operation using the bytes supplies an interpretation. `INT_LESS` compares unsigned values; `INT_SLESS` compares signed values. Both may read the same two varnodes. Ghidra's [SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) also allows varnodes to overlap. In a typical x86-64 Ghidra register layout, the eight-byte `RAX`, four-byte `EAX`, and one-byte `AL` views all begin at register offset zero. A write to the low byte changes one of the bytes seen through the wider view. If a machine instruction also clears the upper half of `RAX` when writing `EAX`, its P-code must express that behavior; overlap alone does not invent the clearing. These are views of storage, not three independent source variables.

<figure class="pcode-visual" id="pcode-register-map">
<figcaption><strong>One register space, several windows.</strong> The columns run from the most significant byte at left to the least significant byte at right. Each bar covers the bytes named by that register view.</figcaption>
<div class="register-ranges" tabindex="0" aria-label="Overlapping x86-64 register byte ranges">
<div class="register-track"><span class="register-track-label">offset</span><span>+7</span><span>+6</span><span>+5</span><span>+4</span><span>+3</span><span>+2</span><span>+1</span><span>+0</span></div>
<div class="register-track"><span class="register-track-label">RAX</span><span class="register-range range-rax">eight bytes</span></div>
<div class="register-track"><span class="register-track-label">EAX</span><span class="register-range range-eax">low four bytes</span></div>
<div class="register-track"><span class="register-track-label">AX</span><span class="register-range range-ax">low two</span></div>
<div class="register-track"><span class="register-track-label">AH</span><span class="register-range range-ah">+1</span></div>
<div class="register-track"><span class="register-track-label">AL</span><span class="register-range range-al">+0</span></div>
<div class="register-track register-byte-values"><span class="register-track-label">bytes</span><output data-register-byte="7">11</output><output data-register-byte="6">22</output><output data-register-byte="5">33</output><output data-register-byte="4">44</output><output data-register-byte="3">55</output><output data-register-byte="2">66</output><output data-register-byte="1">77</output><output data-register-byte="0">88</output></div>
</div>
<div class="lab-presets" id="pcode-register-controls" hidden>
<button type="button" data-register-case="initial" aria-pressed="true">Initial RAX</button>
<button type="button" data-register-case="al" aria-pressed="false">Write AL = aa</button>
<button type="button" data-register-case="ah" aria-pressed="false">Write AH = bb</button>
<button type="button" data-register-case="eax" aria-pressed="false">Write EAX = 12345678</button>
</div>
<p id="pcode-register-result" aria-live="polite"><code>RAX = 0x1122334455667788</code>. Select a write to see which bytes it changes.</p>
<p class="visual-legend">A filled byte was written by the selected view. An outlined byte was cleared by the x86-64 32-bit register-write rule.</p>
</figure>

Try to predict the `AH` case before selecting it: byte `+1` changes, but `AL` at `+0` does not. The `EAX` case makes a different point. Writing a 32-bit x86-64 general-purpose register also clears its upper 32 bits. The four low bytes and the four cleared bytes have different reasons for changing. A varnode overlap check explains the first part; the instruction semantics explain the second. AMD's [architecture manual, section 3.4.5](https://docs.amd.com/api/khub/documents/sfvvekC9mDflu6vd3R0NXA/content), specifies the extension rule for 32-bit results and the preserved high bits for 8- and 16-bit results.

Finally, a **P-code operation** has an opcode, zero or more input varnodes, and sometimes one output varnode. It can read and write those values, or change control flow. The [`PcodeOp` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html) represents that shape directly. One machine instruction can generate many operations because its behavior may include intermediate calculations, flags, memory effects, and a transfer of control.

| Space | How to read a varnode there | Common trap |
| --- | --- | --- |
| `const` | The offset encodes a literal value | Treating it as memory to dereference |
| `register` | Bytes in Ghidra's processor register layout | Assuming two overlapping register views are separate |
| `unique` | Temporary storage used while expressing semantics | Assuming a numeric unique offset is a process address |
| `ram` | Bytes in the named memory space | Treating its address as its contents |

In raw instruction translation, `unique` values are useful scratch space. A SLEIGH author can write a local temporary, and the compiler can allocate its storage in the unique space. [Spinsel's small processor-module walkthrough](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html) shows this in a compact setting: a SLEIGH local turns into a unique-space varnode, with `COPY` and `INT_ADD` operations updating it. This is easier to see in a tiny instruction set before approaching x86 flags.

### Give the triple a precise meaning

Let a varnode be $v=(s,o,n)$: space $s$, offset $o$, and size $n$ bytes. For an ordinary storage space, reading it means taking bytes $o$ through $o+n-1$ from that space's state. Two varnodes overlap when they name the same space and their byte ranges intersect:

$$ {#varnode-overlap}
\operatorname{overlap}(v_1,v_2)
\iff s_1=s_2\ \land\
\max(o_1,o_2)<\min(o_1+n_1,o_2+n_2).
$$

That formula explains why `RAX`, `EAX`, and `AL` cannot be modeled as unrelated variables. It also tells us what a partial write changes: exactly the bytes selected by its output varnode, plus any other writes explicitly present in the translated instruction. Endianness determines how a multi-byte value is assembled from those bytes. For example, four little-endian bytes `78 56 34 12` represent the integer `0x12345678`; the same bytes interpreted big-endian represent `0x78563412`. The space's endianness, not the spelling of `INT_ADD`, chooses the encoding. [Ghidra's P-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html) defines that relationship.

`const` needs its own rule. Its offset is the literal, so `(const, 0xff, 1)` yields `0xff`. It does not read $M_{\mathrm{const}}[0xff]$. This distinction matters again for branch destinations, where a constant-space varnode has a special instruction-local meaning.

### Why a SLEIGH local becomes a unique varnode

Take the semantic body of a toy swap instruction:

~~~c
local tmp:4 = r1;
r1 = r2;
r2 = tmp;
~~~

This follows the temporary-variable pattern in Ghidra's [SLEIGH constructor documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html); it is a semantic fragment, not a complete processor specification. The temporary preserves the old value of `r1` before `r1` is overwritten. A simplified raw translation is:

~~~text
unique[tmp:4] = COPY register[r1:4]
register[r1:4] = COPY register[r2:4]
register[r2:4] = COPY unique[tmp:4]
~~~

Predict the result if the first operation were deleted. The last `COPY` would have no saved original `r1` to read. The `unique` space exists because the description of one machine instruction sometimes needs scratch values that are neither architectural registers nor process RAM. It is best understood as translation-time temporary storage, not as an address you can find in the executable's memory map.

## Widths are part of the meaning

P-code's byte sizes are semantic, not decoration. An `INT_ADD` with two four-byte inputs and a four-byte output computes modulo `2^32`. The corresponding eight-byte operation computes modulo `2^64`. Neither operation silently keeps a ninth byte or sets a processor flag. The [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) defines separate operations such as `INT_CARRY` and `INT_SCARRY` for unsigned carry and signed overflow.

Here is a simplified illustration:

~~~text
out:1 = INT_ADD const[0xff:1], const[0x01:1]   ; out becomes 0x00
cf:1  = INT_CARRY const[0xff:1], const[0x01:1] ; cf becomes true
~~~

The notation above is explanatory, rather than a byte-for-byte dump from Ghidra. The point is that the one-byte result wraps, while carry is a distinct value. When you see an `INT_ZEXT` or `INT_SEXT`, it is also a real semantic step: one fills new high bits with zero; the other repeats the sign bit. `SUBPIECE` drops a specified number of least-significant bytes, and `PIECE` concatenates high and low parts. These operations explain how a language can express register slices and multiword results without inventing new opcodes for each architecture.

The same discipline applies to shifts and comparisons. `INT_RIGHT` is logical right shift; `INT_SRIGHT` is arithmetic right shift. `INT_LESS` and `INT_SLESS` disagree whenever the signed bit changes the ordering. An analyzer that translates every right shift to the same host-language operator, or every comparison to a signed comparison, will produce plausible-looking but incorrect results. The exact width and opcode matter more than the name an analyst assigns to the variable.

Floating-point operations form their own family, including `FLOAT_ADD`, `FLOAT_EQUAL`, conversions, and NaN tests. Their presence does not let a consumer assume that ordinary integer operations are floating-point because a type hint says `double`. Raw P-code works at the operation level; later type recovery is another layer.

Here is a small executable model for the integer rules. Python's integers do not overflow, so the mask is the step that gives a P-code operation its selected width. Run this fragment with `python pcode_widths.py`:

~~~python
def mask(nbytes):
    return (1 << (8 * nbytes)) - 1

def int_add(a, b, nbytes):
    return (a + b) & mask(nbytes)

def signed(bits, nbytes):
    width = 8 * nbytes
    bits &= mask(nbytes)
    sign = 1 << (width - 1)
    return bits - (1 << width) if bits & sign else bits

def int_less(a, b, nbytes):
    return int((a & mask(nbytes)) < (b & mask(nbytes)))

def int_sless(a, b, nbytes):
    return int(signed(a, nbytes) < signed(b, nbytes))

assert int_add(0xff, 1, 1) == 0x00
assert int_add(0xff, 1, 2) == 0x0100
assert int_less(0xff, 1, 1) == 0
assert int_sless(0xff, 1, 1) == 1
~~~

The final two assertions use identical input bits. Under unsigned comparison, `0xff` is $255$; under signed eight-bit comparison, it is $-1$. The code is a teaching model for these opcodes, not a complete emulator. It deliberately leaves out memory, float formats, exceptional cases, and the architecture's instruction sequencing. The test makes one point hard to miss: **the varnode's bytes do not carry a permanent signedness tag**. The operation decides how to read them.

Here is another small decoding exercise. `SUBPIECE` takes its second input as a *byte count* to discard from the low end; `PIECE` takes a high part followed by a low part. These two lines select and then rebuild bytes, with no C type involved:

~~~text
hi:2 = SUBPIECE const[0x12345678:4], const[2:4]  ; hi = 0x1234
whole:4 = PIECE hi:2, const[0xabcd:2]            ; whole = 0x1234abcd
~~~

The tempting mistake is to read `SUBPIECE(..., 2)` as “take two bytes starting from the left.” It actually drops **two least-significant bytes**. This matters when a processor splits a wide register into smaller operations: the byte slice you choose can reverse the meaning of a comparison or memory write. The [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) defines the operand order and width constraints.

## One x86 `TEST` becomes nine operations

Consider this real five-instruction function from a checked-in [x86-64 ELF fixture](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/tests/fixtures/hydir_prism_showcase.S):

~~~asm
hydir_stage_bit_gate:
    mov  $0, %rax
    test %rsi, %rdi
    je   .Lbit_gate_done
    mov  $1, %rax
.Lbit_gate_done:
    ret
~~~

Its result is `1` when `RDI & RSI` is nonzero and `0` otherwise. That short C-like statement hides the flags. The [saved Ghidra snapshot](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/tests/fixtures/ghidra_prism_bit_gate_oracle_v2.json) records **five machine instructions and fifteen raw P-code operations**. The `TEST` at `0x2013d6` alone contributes nine operations.

The following is a readable transcription of those nine operations. It substitutes flag names for the fixture's one-byte register offsets and short names for unique-space offsets; the operation order and calculations come from the saved raw export.

~~~text
0x2013d6  test %rsi, %rdi
    CF = COPY 0
    OF = COPY 0
    t0:8 = INT_AND RDI:8, RSI:8
    SF = INT_SLESS t0:8, 0:8
    ZF = INT_EQUAL t0:8, 0:8
    t1:8 = INT_AND t0:8, 0xff:8
    t2:1 = POPCOUNT t1:8
    t3:1 = INT_AND t2:1, 1:1
    PF = INT_EQUAL t3:1, 0:1

0x2013d9  je 0x2013e2
    CBRANCH 0x2013e2, ZF
~~~

`TEST` computes the AND but does not save that result into either input register. `t0` is temporary storage. The raw translation clears carry and overflow, derives the sign and zero flags, and calculates parity from the low byte. The next instruction reads `ZF`. This is why a hand-written rule saying “`test` is just AND” misses observable state, even if it happens to predict this function's return value.

The flag names in this transcription are for the reader. The actual JSON contains varnodes such as `(register, 0x206, 1)` for the zero flag and `(unique, 0xd5700, 8)` for `t0`, along with each operation's source instruction address and sequence position. The offsets belong to the Ghidra language used for this binary. They are not universal register numbers.

Try two inputs: `RDI = 0x48, RSI = 0x08` gives a nonzero AND, so `ZF = 0` and `JE` falls through to the `mov $1`. Changing `RDI` to `0x40` makes the AND zero, so `ZF = 1` and `JE` goes directly to `ret`. The operations make the condition traceable one value at a time:

~~~text
RDI and RSI  ->  INT_AND  ->  t0  ->  INT_EQUAL(t0, 0)  ->  ZF  ->  CBRANCH
~~~

That chain is also a useful recipe for reading unfamiliar P-code. Start at the branch condition. Find the operation that writes its varnode. Follow the inputs backward until you reach registers, constants, or memory. Only then summarize the condition in C-like language.

Let's calculate every flag the nine operations set. The parity flag tests whether the **low byte** has an even number of set bits. Zero has zero set bits, so its parity is even.

| RDI | RSI | `t0 = RDI & RSI` | SF | ZF | PF | `JE` |
| --- | --- | --- | --- | --- | --- | --- |
| `0x48` | `0x08` | `0x08` | 0 | 0 | 0 | Fall through |
| `0x40` | `0x08` | `0x00` | 0 | 1 | 1 | Take branch |
| `0x8000000000000000` | same | same | 1 | 0 | 1 | Fall through |

In all three rows `CF = OF = 0`. The third row is instructive: the sign bit is set, but the low byte is zero, so `SF = 1` and `PF = 1` at the same time. Flags answer different questions about the same result. Here is a compact Python implementation of the fixture's `TEST` flag behavior:

~~~python
MASK64 = (1 << 64) - 1

def test_flags(rdi, rsi):
    result = (rdi & rsi) & MASK64
    low_byte = result & 0xff
    return {
        "result": result,
        "CF": 0,
        "OF": 0,
        "SF": (result >> 63) & 1,
        "ZF": int(result == 0),
        "PF": int(low_byte.bit_count() % 2 == 0),
    }

assert test_flags(0x48, 0x08)["ZF"] == 0
assert test_flags(0x40, 0x08)["ZF"] == 1
assert test_flags(1 << 63, 1 << 63)["SF"] == 1
~~~

<section class="lab" id="pcode-test-lab" aria-labelledby="pcode-test-heading" hidden>
<h3 id="pcode-test-heading">Try the P-code chain</h3>
<p>Enter two 64-bit hexadecimal values. The output follows the <code>INT_AND</code>, flag writes, and <code>CBRANCH</code> in the real <code>TEST</code> example.</p>
<div class="lab-controls">
<label>RDI in hex <input id="pcode-rdi" type="text" value="0x48" inputmode="text" spellcheck="false"></label>
<label>RSI in hex <input id="pcode-rsi" type="text" value="0x08" inputmode="text" spellcheck="false"></label>
</div>
<div class="lab-presets">
<button type="button" data-pcode-preset="0x48,0x08">Nonzero AND</button>
<button type="button" data-pcode-preset="0x40,0x08">Zero AND</button>
<button type="button" data-pcode-preset="0x8000000000000000,0x8000000000000000">Sign bit</button>
</div>
<p id="pcode-test-error" role="status"></p>
<h4>Final state for these inputs</h4>
<p class="lab-result">Temporary <code>t0</code> = <output id="pcode-and">0x08</output></p>
<dl class="flag-row">
<div><dt>CF</dt><dd><output id="pcode-cf">0</output></dd></div>
<div><dt>OF</dt><dd><output id="pcode-of">0</output></dd></div>
<div><dt>SF</dt><dd><output id="pcode-sf">0</output></dd></div>
<div><dt>ZF</dt><dd><output id="pcode-zf">0</output></dd></div>
<div><dt>PF</dt><dd><output id="pcode-pf">0</output></dd></div>
</dl>
<p>At <code>0x2013d9</code>, <output id="pcode-branch">JE falls through</output>.</p>
<div class="pcode-stepper">
<h4>Step through the raw operations</h4>
<p>The first nine entries share source address <code>0x2013d6</code>; the last is the next machine instruction at <code>0x2013d9</code>. The list uses one-based teaching numbers; the exported operation sequence times start at zero.</p>
<div class="lab-presets">
<button type="button" id="pcode-step-prev">Previous</button>
<button type="button" id="pcode-step-next">Next operation</button>
<button type="button" id="pcode-step-reset">Start again</button>
<output id="pcode-step-count">Before operation 1 of 10</output>
</div>
<ol class="pcode-operation-list">
<li data-pcode-op="1"><code>CF = COPY 0</code></li>
<li data-pcode-op="2"><code>OF = COPY 0</code></li>
<li data-pcode-op="3"><code>t0 = INT_AND RDI, RSI</code></li>
<li data-pcode-op="4"><code>SF = INT_SLESS t0, 0</code></li>
<li data-pcode-op="5"><code>ZF = INT_EQUAL t0, 0</code></li>
<li data-pcode-op="6"><code>t1 = INT_AND t0, 0xff</code></li>
<li data-pcode-op="7"><code>t2 = POPCOUNT t1</code></li>
<li data-pcode-op="8"><code>t3 = INT_AND t2, 1</code></li>
<li data-pcode-op="9"><code>PF = INT_EQUAL t3, 0</code></li>
<li data-pcode-op="10"><code>CBRANCH 0x2013e2, ZF</code></li>
</ol>
<p class="step-explanation" id="pcode-step-explanation" aria-live="polite">Before operation 1, these flags have not yet been written by this instruction.</p>
</div>
</section>

This little experiment is intentionally narrower than running an ELF. It computes the raw `TEST` effect on supplied register values. It does not claim anything about where a larger program obtained those values.

## Memory has two addresses in the picture

The printed shape of a `LOAD` can be misleading. It has a special first input naming the **space being accessed**, a second input holding a **pointer offset**, and an output whose size determines how many bytes to read. `STORE` similarly has a destination space, pointer offset, and value whose size determines the write width. The [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) calls out this distinction explicitly.

For illustration, imagine an eight-byte pointer in a register, and a four-byte read from RAM:

~~~text
ptr:8 = INT_ADD base:8, const[0x10:8]
value:4 = LOAD spaceid(ram), ptr:8
~~~

`ptr` is stored in some varnode, perhaps in `register` or `unique`. Its numeric **contents** give an offset into the RAM space named by `spaceid(ram)`. The four-byte output sets the read width. The address space containing the `ptr` varnode can differ from the address space being loaded. `spaceid(ram)` is explanatory notation here; a raw dump encodes that space ID in a special constant input.

On common x86-64 languages an addressable RAM unit is a byte. Ghidra's definition also allows a space whose addressable unit is larger. For those spaces, `LOAD` and `STORE` scale the pointer offset by the space's word size to obtain a byte offset. An emulator that assumes every space is byte-addressed can read the wrong location while still producing a perfectly well-formed P-code trace.

The raw `RET` in our fixture makes the two roles of `const` unusually clear. Here are its three operations, with the exact exported offsets. This fixture's address-space table maps ID `0x1b1` to `ram`.

~~~text
0x2013e2:
  (register,0x288,8) = LOAD (const,0x1b1,8), (register,0x20,8)
  (register,0x20,8)  = INT_ADD (register,0x20,8), (const,0x8,8)
  RETURN (register,0x288,8)
~~~

Read the first line slowly. `(register,0x20,8)` holds the stack pointer value. `(const,0x1b1,8)` is the special **space ID operand** to `LOAD`; it selects RAM. `(register,0x288,8)` receives the eight bytes loaded from that stack address. In the next line, `(const,0x8,8)` is an ordinary numeric eight, and the stack pointer advances. The final operation transfers control to the value just loaded. The same `const` space appears in both lines, but the opcode and operand position determine whether its offset is a space selector or a literal arithmetic input.

<figure class="pcode-visual" id="pcode-load-lab">
<figcaption><strong>Trace the two inputs to <code>LOAD</code>.</strong> This is a teaching seed with <code>RSP = 0x700000</code> and supplied little-endian stack bytes. It is not a claim that these bytes occur in the fixture ELF.</figcaption>
<div class="load-inputs">
<div><span>Input 0 · space selector</span><code>(const, 0x1b1, 8)</code><strong>RAM</strong></div>
<div><span>Input 1 · pointer value</span><code>(register, 0x20, 8)</code><strong>0x700000</strong></div>
</div>
<p class="load-action"><code>LOAD</code> reads eight bytes from <code>ram[0x700000]</code> ↓</p>
<div class="load-byte-row" tabindex="0" aria-label="Eight consecutive stack bytes, lowest address first">
<div><span>+0</span><output data-load-byte="0">ef</output></div>
<div><span>+1</span><output data-load-byte="1">be</output></div>
<div><span>+2</span><output data-load-byte="2">ad</output></div>
<div><span>+3</span><output data-load-byte="3">de</output></div>
<div><span>+4</span><output data-load-byte="4">00</output></div>
<div><span>+5</span><output data-load-byte="5">00</output></div>
<div><span>+6</span><output data-load-byte="6">00</output></div>
<div><span>+7</span><output data-load-byte="7">00</output></div>
</div>
<div class="lab-presets" id="pcode-load-controls" hidden>
<button type="button" data-load-case="known" aria-pressed="true">All bytes supplied</button>
<button type="button" data-load-case="missing" aria-pressed="false">Byte +3 unknown</button>
</div>
<p id="pcode-load-result" aria-live="polite">The loaded value is <code>0x00000000deadbeef</code>. A separate mapping check would be needed before treating it as an executable return target.</p>
</figure>

Remove byte `+3` in the diagram. Seven known bytes cannot determine the eight-byte value: the unknown byte occupies bits 24 through 31. Filling it with zero would turn a missing observation into a made-up return address. The `LOAD` operation defines the read, but the initial state defines whether that read has a known result.

For a word-addressed space, the pointer conversion is:

$$ {#pcode-word-addressing}
\operatorname{byteOffset}=\operatorname{pointerOffset}\times\operatorname{wordsize}.
$$

If `wordsize = 2` and the pointer offset is `0x10`, `LOAD` starts at byte offset `0x20`. This scaling is specific to dereferencing through `LOAD` or `STORE`; it is not a license to multiply every P-code address by two. [Ghidra's reference manual](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html) makes that exception explicit.

There is a second memory question that P-code alone cannot answer: **what bytes are there?** A `LOAD` specifies where to read and how much to read. It does not promise that a file has initialized those bytes, that a pointer is mapped, or that a previous call has a known effect. A decompiler can reason symbolically about the load. A concrete emulator needs an initial state or an explicit unknown result.

For the x86-64 fixture's little-endian RAM, a minimal read can be written this way:

~~~python
def load_le(known_bytes, address, size):
    missing = [address + i for i in range(size)
               if address + i not in known_bytes]
    if missing:
        raise ValueError(f"unknown memory byte at {missing[0]:#x}")
    return sum(known_bytes[address + i] << (8 * i)
               for i in range(size))

stack = {
    0x700000 + i: byte
    for i, byte in enumerate((0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0))
}
assert load_le(stack, 0x700000, 8) == 0xdeadbeef
~~~

The check for missing bytes is the important line. Replacing it with `known_bytes.get(address + i, 0)` would quietly turn unknown memory into a zero-filled stack. That would let an emulator “succeed” on a state nobody supplied. Real process modeling also needs mapped segments, permissions, and writes, but the small example already shows why a P-code `LOAD` cannot manufacture its own input.

## Branches, calls, and returns have precise quirks

`BRANCH` uses its destination varnode as an address descriptor, not as a normal value to read. `CBRANCH` adds a one-byte condition: nonzero means take the branch. If the destination is in the **constant** space, it has a special meaning: a relative jump among the P-code operations generated for the *current machine instruction*. It is not a jump to a constant machine address. Ghidra's [branch definitions](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) give the example of operation 5 moving to operation 8 with a relative offset of 3.

Here is that example drawn as an operation list:

~~~text
machine instruction at 0x401000
  op 5: CBRANCH (const,+3), condition
  op 6: ...                 # condition was false
  op 7: ...
  op 8: ...                 # condition was true
~~~

When `condition` is true, `op 5 + 3` selects `op 8` **inside the translation of the same machine instruction**. It does not execute machine address `0x3` or `0x401003`. Why would an instruction need this? A SLEIGH specification may describe a conditional choice or loop inside one architectural instruction. Its [constructor documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html) shows labels and conditional jumps inside a semantic section; the compiler encodes those label jumps as P-code-relative indices. A tool that only records instruction-to-instruction edges can miss this smaller control-flow layer.

`BRANCHIND` gets the target offset from a varnode at runtime. That is the form to watch around jump tables and computed dispatch. The current address space supplies the target space. Without the runtime value or a sound finite target set, there may be more destinations than a static listing currently shows.

`CALL`, `CALLIND`, and `RETURN` sound more high level than their **raw** behavior. The reference describes raw `CALL` as a branch marked as call-like for analysis; it does not push a return address onto a hidden P-code call stack. Raw `RETURN` is likewise a return-like indirect branch. The machine instruction's other P-code operations carry effects such as saving or loading a return address. In our x86 fixture, `ret` has a `LOAD` from the stack, an `INT_ADD` that advances `RSP` by eight, and `RETURN`. Reading only the last operation would drop two parts of the instruction.

These details matter when emulating or lifting. The presence of a `CALL` marker can guide function recovery, while actual calling conventions, stack state, argument locations, and imported effects require additional information. It also matters for security analysis: a single observed indirect-call target tells you where one run went, not everywhere the program could go.

## Raw P-code versus high P-code

**Raw P-code** is obtained from instruction translation. It keeps the small operations that express the instruction's immediate effects, including flags and temporary values. Ghidra exposes it through the [`Instruction.getPcode` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html). A `PcodeOp` also carries a [sequence number](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/SequenceNumber.html) tied to the source instruction address and a position among that instruction's operations. That lets a reader point to the machine instruction behind an operation rather than merely saying “somewhere in the function.”

**High P-code** is produced after the decompiler has analyzed control and data flow. Values can acquire SSA-style identity, variable names, and type information. Operations may be simplified, rewritten, or removed when they do not contribute to the decompiler's chosen output. Ghidra exposes the resulting operations through a [`HighFunction`](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html). The same five-instruction fixture has fifteen raw operations but only four operations in its optional high-P-code export. That difference is expected: the high view has turned the flag-and-branch sequence into a compact value expression and no longer shows every stack effect in the raw `ret` translation.

Some opcodes appear only after analysis. Ghidra's [additional operations page](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html) lists several especially helpful ones:

| High-P-code operation | What it tells you |
| --- | --- |
| `MULTIEQUAL` | An SSA phi: choose the incoming value from the predecessor actually taken |
| `INDIRECT` | A value may have changed through an effect that analysis cannot directly express, such as an alias |
| `PTRADD` | Pointer arithmetic recognized as an array index and element stride |
| `PTRSUB` | Pointer arithmetic recognized as an offset into a structure |
| `CAST` | The bits are copied, but their inferred type interpretation changes |

Let's build a phi node by hand. Suppose a function's control flow is:

~~~c
if (condition) {
    x = 4;
} else {
    x = 9;
}
return x;
~~~

At the merge block, raw P-code contains the branch and the concrete writes that implement each path. The decompiler can give each reaching value a distinct identity and insert a high-P-code merge:

~~~text
true predecessor:  x1 = COPY 4
false predecessor: x2 = COPY 9
merge block:       x3 = MULTIEQUAL x1, x2
                   RETURN x3
~~~

The operation means “select the input associated with the predecessor actually taken.” It does **not** mean add `4 + 9`, pick either value at random, or execute a new instruction at the merge. The incoming edge determines the selection. In SSA notation, we write $x_3=\phi(x_1,x_2)$. That explicit definition is why a backward slice can follow `x3` to both possible sources. This example is schematic; the exact printed high P-code for a compiled function depends on Ghidra's analysis and simplification style.

<figure class="pcode-visual pcode-phi" id="pcode-phi-lab">
<figcaption><strong>Follow the edge into the merge.</strong> The selected predecessor supplies the value of <code>x3</code>. The phi belongs to the analyzed dataflow graph; it is not another machine instruction.</figcaption>
<div class="diagram">
<svg viewBox="0 0 600 500" role="img" aria-labelledby="phi-title phi-desc">
<title id="phi-title">Two paths feed one MULTIEQUAL operation</title>
<desc id="phi-desc">A condition leads to a true block defining x1 as 4 or a false block defining x2 as 9. The selected predecessor flows into a merge block that defines x3 using MULTIEQUAL, then returns x3.</desc>
<defs><marker id="phi-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8 Z" class="phi-arrowhead"/></marker></defs>
<path id="phi-edge-true" class="phi-edge is-active" d="M250 85 L150 175" marker-end="url(#phi-arrow)"/>
<path id="phi-edge-false" class="phi-edge" d="M350 85 L450 175" marker-end="url(#phi-arrow)"/>
<path id="phi-merge-true" class="phi-edge is-active" d="M150 250 L240 335" marker-end="url(#phi-arrow)"/>
<path id="phi-merge-false" class="phi-edge" d="M450 250 L360 335" marker-end="url(#phi-arrow)"/>
<path class="phi-edge" d="M300 415 L300 450" marker-end="url(#phi-arrow)"/>
<g class="phi-node"><rect x="200" y="20" width="200" height="65"/><text x="300" y="60" text-anchor="middle">condition?</text></g>
<g id="phi-node-true" class="phi-node is-active"><rect x="55" y="180" width="190" height="70"/><text x="150" y="222" text-anchor="middle">x1 = 4</text></g>
<g id="phi-node-false" class="phi-node"><rect x="355" y="180" width="190" height="70"/><text x="450" y="222" text-anchor="middle">x2 = 9</text></g>
<g class="phi-node"><rect x="180" y="340" width="240" height="75"/><text x="300" y="370" text-anchor="middle">x3 = MULTIEQUAL</text><text x="300" y="397" text-anchor="middle">(x1, x2)</text></g>
<text x="300" y="483" text-anchor="middle">return x3</text>
<text class="annotation" x="72" y="134">true edge</text>
<text class="annotation" x="438" y="134">false edge</text>
</svg>
</div>
<div class="lab-presets" id="pcode-phi-controls" hidden>
<button type="button" data-phi-path="true" aria-pressed="true">Take true edge</button>
<button type="button" data-phi-path="false" aria-pressed="false">Take false edge</button>
</div>
<p id="pcode-phi-result" aria-live="polite">Arrived from the true block: <code>x3 = 4</code>.</p>
</figure>

Now consider a different high-level clue: `PTRADD(base, i, 12)`. Its numeric calculation is `base + i * 12`, but its opcode says more: analysis currently treats `base` as an array pointer with twelve-byte elements. `PTRSUB(element, 8)` computes `element + 8` and expresses a proposed field offset inside a structured value. A decompiler might combine them into `array[i].field`. The raw P-code may show only multiplies, additions, and a `LOAD`. Those richer pointer operations help explain recovered C, while the numeric offsets remain worth checking against the original accesses. [Ghidra's additional-opcode reference](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html) spells out both calculations.

This is why the two views serve different tasks. If you want to **emulate exact instruction effects**, raw P-code is the natural starting point. If you want to **trace a value through a function** or find a type-aware pattern, high P-code often saves a great deal of work. [A gentle introduction to static analysis with P-code](https://v0iddeck.com/articles/static-analysis-ghidra-pcode) uses the latter for taint-style traversal; [twevs' high-P-code case study](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html) uses it to identify PlayStation graphics patterns that would be awkward to recover from isolated machine instructions.

High P-code is not one immutable snapshot either. Ghidra's [`DecompInterface.setSimplificationStyle` API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html) exposes styles such as `firstpass`, `normalize`, and `decompile`. `firstpass` gives a largely unmodified dataflow syntax tree, `normalize` omits type recovery and some final cleanup, and the default `decompile` performs the work aimed at C output. An analysis script that needs an early stack copy may obtain a different operation set from one that asks for final C-oriented high P-code. Record the style when you compare results; otherwise two correct screenshots can appear to contradict each other.

There is a price for that convenience. [NCC Group's Ghostrings investigation](https://www.nccgroup.com/research/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/) found that a decompiler simplification stage could remove stack-copy operations its Go-string recovery wanted to inspect. [PracticalPCode](https://github.com/kohnakagawa/PracticalPCode) shows a successful use of high-level dataflow to recover dynamically resolved Win32 API names. Both examples reward asking which stage of P-code you are reading and what transformations happened before your script received it.

## Why P-code cannot simply be renamed LLVM IR

This question comes up whenever someone wants to lift a binary into a compiler. Both P-code and LLVM IR have operations called “add” and “load.” Their surrounding contracts differ. Raw P-code can write overlapping architectural register bytes, uses named machine address spaces, and carries instruction-local control flow. LLVM IR gives computations SSA values and its own pointer, memory, and undefined-behavior rules. Translation needs a model for those differences.

Consider an eight-bit P-code `INT_ADD`. Its result is the low eight bits of the sum. A corresponding LLVM fragment can use an ordinary `add i8`:

~~~llvm
%sum = add i8 %a, %b
%carry = icmp ult i8 %sum, %a
~~~

The second line calculates unsigned carry for this addition. In an LLVM lift, the carry must be represented because a later machine branch may read it. Adding LLVM's `nsw` flag to the first line would assert that signed overflow cannot occur; if it does, LLVM produces a poison value. P-code's plain `INT_ADD` makes no such promise. The [LLVM language reference](https://llvm.org/docs/LangRef.html) defines these flags and poison behavior. A lift that adds `nsw` just because the machine instruction looked like ordinary C arithmetic has changed the program.

The pointer story is similar. High P-code `PTRADD` can encode an inferred array stride, while LLVM's `getelementptr` computes addresses under LLVM's pointer rules. Qualifiers such as `inbounds` introduce additional conditions whose violation can produce poison; the [LLVM GEP guide](https://llvm.org/docs/GetElementPtr.html) explains why this is more than decorative syntax. Machine pointer arithmetic may wrap or target bytes that do not belong to a recovered C object. A lifter has to justify each stronger LLVM claim, or keep a more explicit machine-state representation.

This contrast also explains why **high P-code is attractive for understanding C** and **raw P-code is attractive for checking instruction effects**. Each has removed a different amount of machine detail. Neither turns an unfamiliar binary into a well-typed, exception-free LLVM program by simple opcode substitution.

## How to inspect it yourself

You can enable a P-code field in Ghidra's Listing. [Spinsel's walkthrough](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html) shows the field setup, including the “Display Raw Pcode” option. The listing is ideal for answering “what does this instruction do?” For repeatable inspection, save the following as a Ghidra Java script named `ExplainOneInstruction.java`. Put the cursor on an instruction and run it:

~~~java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class ExplainOneInstruction extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Instruction ins =
            currentProgram.getListing().getInstructionAt(currentAddress);
        if (ins == null) {
            println("Put the cursor on a decoded instruction.");
            return;
        }

        println(ins.getAddress() + "  " + ins.getMnemonicString());
        for (PcodeOp op : ins.getPcode(true)) {
            println("  #" + op.getSeqnum().getTime()
                    + "  " + op.getMnemonic()
                    + "  output=" + op.getOutput());
            for (int i = 0; i < op.getNumInputs(); i++) {
                println("      input[" + i + "]=" + op.getInput(i));
            }
        }
    }
}
~~~

The `true` argument requests the version that includes Ghidra's flow overrides, as documented by the [`Instruction` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html). The script prints the opcode and each input separately because operand position can change meaning, as it did for `LOAD`'s special space ID. `getSeqnum().getTime()` distinguishes operations at the same machine instruction address. If you are building an analyzer, inspect these structured fields; parsing `op.toString()` is fragile.

To see the *analyzed* view, use a different API. Save this as `ExplainHighPcode.java` and place the cursor inside a function:

~~~java
import java.util.Iterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

public class ExplainHighPcode extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Function fn = currentProgram.getFunctionManager()
                                    .getFunctionContaining(currentAddress);
        if (fn == null) {
            println("Put the cursor inside a function.");
            return;
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(currentProgram)) {
                println("Could not open the program in the decompiler.");
                return;
            }
            DecompileResults results =
                decompiler.decompileFunction(fn, 30, monitor);
            if (!results.decompileCompleted()) {
                println(results.getErrorMessage());
                return;
            }
            HighFunction high = results.getHighFunction();
            if (high == null) {
                println("Decompilation produced no HighFunction.");
                return;
            }
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                println(op.getSeqnum().getTarget() + "  " + op);
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    println("    input[" + i + "] " + input
                            + " <- " + input.getDef());
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
~~~

This script prints high P-code in Ghidra's `decompile` style. The [`DecompInterface` API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html) documents opening the program, checking completion, and obtaining `HighFunction`. Each `input.getDef()` points to the high-P-code operation that defined that input, when one is available. A constant or live-in value may have no local definition. Try changing the simplification style to `normalize` and compare the operation set. A high varnode's definition and uses can be followed through [`Varnode.getDef()` and `getDescendants()`](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html). The operation iterator alone is not an execution trace; branches and `MULTIEQUAL` inputs still require control-flow context.

A useful inspection order is: locate the source instruction; read the raw operations and their widths; map register varnodes through the selected language; follow the high-P-code value chain if you need cross-block context; then compare the resulting C-like expression with the original effects. This order catches errors caused by trusting a nice-looking expression before checking how it was derived.

## Where P-code's model stops

P-code has a defined vocabulary, but some effects are intentionally represented as placeholders. `CALLOTHER` identifies a language-defined user operation. Its name and inputs do not automatically specify every side effect. Ghidra's [pseudo-operation reference](https://ghidra.re/ghidra_docs/languages/html/pseudo-ops.html) says such an operation may need architecture-specific handling or conservative black-box treatment. That is a meaningful warning for unusual instructions, hardware interactions, and virtualized or obfuscated code.

Likewise, `INT_DIV` defines an unsigned quotient but leaves division-by-zero behavior to surrounding modeling; the [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) does not make it an automatic processor trap. A direct call marker does not tell you what an imported library routine changes. A `LOAD` does not populate missing memory. High P-code can introduce type and alias assumptions that make a function readable while losing an effect a particular analysis wanted to observe.

Researchers have studied these edges formally. [Naus, Verbeek, Walker, and Ravindran's P-code semantics work](https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7) examines **high** P-code and the information needed to give it executable meaning. Its scope matters: findings about a decompiler-transformed representation should not be casually applied to every raw operation. The practical lesson is to name the P-code stage, the selected language, and the state assumptions behind any claimed execution result.

John Toterhi's [Ghidra P-code emulation walkthrough](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb) makes that state requirement concrete by setting up registers, memory, a starting address, and steps in Ghidra's emulator. It is a useful bridge between reading a listing and asking “what would these operations do for this input?” An emulator answers that question for a supplied state and path. Static analysis asks a broader question about many possible states.

### The experiment has a boundary

Imagine you seed `RDI = 0x48` and `RSI = 0x08` at our function's entry. The nine `TEST` operations determine the flags. The branch determines the next instruction. But the later `RET` reads eight bytes from `RSP`. Unless a caller or test harness supplied those stack bytes, the return destination remains unknown. We can state the experiment as a small transition system:

$$ {#pcode-state-step}
S_{i+1}=F_{\mathrm{op}_i}(S_i),\qquad
S_i=(R_i,M_i,\mathrm{pc}_i).
$$

Here $R$ is register and temporary state, $M$ is memory, and $\mathrm{pc}$ identifies the current P-code operation or machine instruction. The function $F_{\mathrm{op}_i}$ is only defined for the inputs the operation actually has. For our `RET`, that includes eight readable stack bytes. We can calculate `ZF` from two registers without knowing the stack; we cannot calculate the return destination from those registers alone. This distinction prevents a local result from being mistaken for a whole-program result.

Ghidra's own [debugger emulation guide](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/B2-Emulation.html) offers a useful warning: emulating a program image only approximates the operating system's loader, external library linkage needs additional modeling, and some uninitialized reads can appear as stale zero values in that workflow. The same guide notes that some language specifications were optimized for decompilation and can contain user operations an emulator cannot execute without handlers. [VoidStar's password-cracking walkthrough](https://voidstarsec.com/blog/ghidra-pcode) is a practical example of the power of seeded emulation: when the state and scope are chosen carefully, P-code can evaluate a difficult routine without running the entire target program.

When reading an emulation result, ask four questions in order:

1. **Which instruction and P-code operation did it start from?** An address alone can hide multiple operations and instruction-local branches.
2. **Which register and memory bytes were supplied?** A register name is not a value, and a mapped page is not necessarily initialized data.
3. **Which external effects were modeled?** Imports, system calls, and `CALLOTHER` do not acquire behavior merely because execution reached them.
4. **What was actually observed?** A successful local path shows behavior for that seed. It does not prove that every path has been explored.

## A brief note on HydIR

HydIR uses Ghidra automatically as a frontend and imports **raw** P-code with source bytes, addresses, varnodes, operation order, and register-space information. The raw operations feed its Rust semantics and bounded lift; Ghidra's optional high P-code is kept as separate decompiler evidence. This follows the division above: a concise high-level value is useful for explanation, while the ordered raw effects are what a concrete executor must account for.

For the `TEST` example, the useful HydIR question is specific: given `RDI = 0x48` and `RSI = 0x08`, does the modeled path set `ZF` to zero and fall through at `0x2013d9`? With `RDI = 0x40`, does it take the branch? Both paths were run against the saved fixture. If a necessary memory byte, user operation, or target is unknown, the result reports that source site instead of inventing a continuation. Readers who want the implementation can inspect the [exporter](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/integrations/ghidra/HydIRSnapshot.java) and [P-code model](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/crates/hydir-ir/src/pcode.rs).

P-code is valuable because it makes small effects visible. Once you learn to read a varnode's space and width, follow an output into the next operation, and distinguish instruction translation from decompiler analysis, a mysterious line of C becomes a chain you can inspect. That skill transfers to emulator scripts, slicing, decompiler debugging, and any framework built on Ghidra's frontend.

## Reading list

- [Ghidra's SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), [pseudo operations](https://ghidra.re/ghidra_docs/languages/html/pseudo-ops.html), and [analysis-only operations](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html): the definitive definitions used throughout this article.
- [Emulating Ghidra's PCode: Why/How](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb): a worked introduction to seeded P-code emulation.
- [Ghidra's debugger emulation guide](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/B2-Emulation.html) and [VoidStar's scripting walkthrough](https://voidstarsec.com/blog/ghidra-pcode): practical state, environment, and user-operation examples.
- [Implementing a brainfuck CPU in Ghidra, part 2](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html): a small SLEIGH example that shows where unique varnodes come from and how to view raw P-code.
- [A Gentle Introduction to Static Analysis with Ghidra Pcode](https://v0iddeck.com/articles/static-analysis-ghidra-pcode) and [using high P-code to detect patterns](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html): practical high-P-code dataflow examples.
- [NCC Group's earlyremoval investigation](https://www.nccgroup.com/research/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/) and [PracticalPCode](https://github.com/kohnakagawa/PracticalPCode): examples of what high-P-code transformation can hide and what it can make tractable.
- [A Formal Semantics for P-Code](https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7): a research treatment of high-P-code semantics.
- [LLVM Language Reference](https://llvm.org/docs/LangRef.html) and [GetElementPtr FAQ](https://llvm.org/docs/GetElementPtr.html): the precise contracts behind the P-code-to-LLVM comparison.

The concrete `TEST` sequence and operation counts above come from HydIR's [checked-in Ghidra snapshot](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/tests/fixtures/ghidra_prism_bit_gate_oracle_v2.json), examined at repository revision [`34dbb5b`](https://github.com/Achxy/hydir-2/tree/34dbb5b11d71e43feb10e8e83e87f307b92012eb). The flag-name transcription is editorial; the snapshot retains the exact register and unique-space offsets.
