An instruction such as `test %rsi, %rdi` looks small in assembly. Underneath, it computes a bitwise result, sets several flags, and gives a later branch a condition to read. A decompiler eventually turns the sequence into something like `(a & b) != 0`. **P-code is the representation Ghidra uses between those two views.** It gives the effects of an instruction as a sequence of simpler operations over registers, memory, constants, and temporary values.

This article is a field guide to reading that representation. We will unpack varnodes, address spaces, widths, memory operations, branches, calls, and the distinction between raw and high P-code. A real x86-64 function gives us an example with actual addresses and operations. Near the end, we will see why these details matter when another tool, including HydIR, consumes Ghidra's output.

The best reference while reading is Ghidra's own [SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), [P-code operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), and [additional operation reference](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html). The manual defines the model; the operation pages settle questions that a printed line of P-code often leaves ambiguous.

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

Finally, a **P-code operation** has an opcode, zero or more input varnodes, and sometimes one output varnode. It can read and write those values, or change control flow. The [`PcodeOp` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html) represents that shape directly. One machine instruction can generate many operations because its behavior may include intermediate calculations, flags, memory effects, and a transfer of control.

| Space | How to read a varnode there | Common trap |
| --- | --- | --- |
| `const` | The offset encodes a literal value | Treating it as memory to dereference |
| `register` | Bytes in Ghidra's processor register layout | Assuming two overlapping register views are separate |
| `unique` | Temporary storage used while expressing semantics | Assuming a numeric unique offset is a process address |
| `ram` | Bytes in the named memory space | Treating its address as its contents |

In raw instruction translation, `unique` values are useful scratch space. A SLEIGH author can write a local temporary, and the compiler can allocate its storage in the unique space. [Spinsel's small processor-module walkthrough](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html) shows this in a compact setting: a SLEIGH local turns into a unique-space varnode, with `COPY` and `INT_ADD` operations updating it. This is easier to see in a tiny instruction set before approaching x86 flags.

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

## Memory has two addresses in the picture

The printed shape of a `LOAD` can be misleading. It has a special first input naming the **space being accessed**, a second input holding a **pointer offset**, and an output whose size determines how many bytes to read. `STORE` similarly has a destination space, pointer offset, and value whose size determines the write width. The [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) calls out this distinction explicitly.

For illustration, imagine an eight-byte pointer in a register, and a four-byte read from RAM:

~~~text
ptr:8 = INT_ADD base:8, const[0x10:8]
value:4 = LOAD spaceid(ram), ptr:8
~~~

`ptr` is stored in some varnode, perhaps in `register` or `unique`. Its numeric **contents** give an offset into the RAM space named by `spaceid(ram)`. The four-byte output sets the read width. The address space containing the `ptr` varnode can differ from the address space being loaded. `spaceid(ram)` is explanatory notation here; a raw dump encodes that space ID in a special constant input.

On common x86-64 languages an addressable RAM unit is a byte. Ghidra's definition also allows a space whose addressable unit is larger. For those spaces, `LOAD` and `STORE` scale the pointer offset by the space's word size to obtain a byte offset. An emulator that assumes every space is byte-addressed can read the wrong location while still producing a perfectly well-formed P-code trace.

There is a second memory question that P-code alone cannot answer: **what bytes are there?** A `LOAD` specifies where to read and how much to read. It does not promise that a file has initialized those bytes, that a pointer is mapped, or that a previous call has a known effect. A decompiler can reason symbolically about the load. A concrete emulator needs an initial state or an explicit unknown result.

## Branches, calls, and returns have precise quirks

`BRANCH` uses its destination varnode as an address descriptor, not as a normal value to read. `CBRANCH` adds a one-byte condition: nonzero means take the branch. If the destination is in the **constant** space, it has a special meaning: a relative jump among the P-code operations generated for the *current machine instruction*. It is not a jump to a constant machine address. Ghidra's [branch definitions](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) give the example of operation 5 moving to operation 8 with a relative offset of 3.

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

Suppose two branches define different values for `x` before merging. A high-P-code `MULTIEQUAL` can express the merge explicitly; a raw instruction sequence would instead show the writes and branches that produced it. The phi node is extremely useful for backward slicing. It is also a decompiler construct, not an instruction the CPU executes. Similarly, `PTRADD(base, i, 12)` says the decompiler recognized an array element stride of twelve bytes. It is more informative than a raw multiply and add, but it rests on type and dataflow analysis.

This is why the two views serve different tasks. If you want to **emulate exact instruction effects**, raw P-code is the natural starting point. If you want to **trace a value through a function** or find a type-aware pattern, high P-code often saves a great deal of work. [A gentle introduction to static analysis with P-code](https://v0iddeck.com/articles/static-analysis-ghidra-pcode) uses the latter for taint-style traversal; [twevs' high-P-code case study](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html) uses it to identify PlayStation graphics patterns that would be awkward to recover from isolated machine instructions.

There is a price for that convenience. [NCC Group's Ghostrings investigation](https://www.nccgroup.com/research/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/) found that a decompiler simplification stage could remove stack-copy operations its Go-string recovery wanted to inspect. [PracticalPCode](https://github.com/kohnakagawa/PracticalPCode) shows a successful use of high-level dataflow to recover dynamically resolved Win32 API names. Both examples reward asking which stage of P-code you are reading and what transformations happened before your script received it.

## How to inspect it yourself

You can enable a P-code field in Ghidra's Listing. [Spinsel's walkthrough](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html) shows the field setup, including the “Display Raw Pcode” option. The listing is ideal for asking what one instruction does. For a script, the core raw API call is short:

~~~java
// GhidraScript fragment. Run with a program open.
Instruction ins = currentProgram.getListing().getInstructionAt(toAddr(0x2013d6L));
for (PcodeOp op : ins.getPcode(true)) {
    println(op.getSeqnum().getTarget() + "  " + op);
}
~~~

The `true` argument requests the version that includes Ghidra's flow overrides, as documented by the [`Instruction` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html). In a real script, check for a missing instruction and import the relevant Ghidra classes. Use `op.getOpcode()`, `getInput(i)`, `getOutput()`, and `getSeqnum()` if you need structured data; parsing the printed line is fragile.

For high P-code, decompile a function through `DecompInterface`, obtain its `HighFunction`, and iterate `getPcodeOps()`. [The high-P-code pattern article](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html) includes a concrete Java example. A high varnode's definition and uses can be followed through [`Varnode.getDef()` and `getDescendants()`](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html). That is the basic machinery behind many backward-slicing and dataflow scripts.

A useful inspection order is: locate the source instruction; read the raw operations and their widths; map register varnodes through the selected language; follow the high-P-code value chain if you need cross-block context; then compare the resulting C-like expression with the original effects. This order catches errors caused by trusting a nice-looking expression before checking how it was derived.

## Where P-code's model stops

P-code has a defined vocabulary, but some effects are intentionally represented as placeholders. `CALLOTHER` identifies a language-defined user operation. Its name and inputs do not automatically specify every side effect. Ghidra's [pseudo-operation reference](https://ghidra.re/ghidra_docs/languages/html/pseudo-ops.html) says such an operation may need architecture-specific handling or conservative black-box treatment. That is a meaningful warning for unusual instructions, hardware interactions, and virtualized or obfuscated code.

Likewise, `INT_DIV` defines an unsigned quotient but leaves division-by-zero behavior to surrounding modeling; the [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html) does not make it an automatic processor trap. A direct call marker does not tell you what an imported library routine changes. A `LOAD` does not populate missing memory. High P-code can introduce type and alias assumptions that make a function readable while losing an effect a particular analysis wanted to observe.

Researchers have studied these edges formally. [Naus, Verbeek, Walker, and Ravindran's P-code semantics work](https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7) examines **high** P-code and the information needed to give it executable meaning. Its scope matters: findings about a decompiler-transformed representation should not be casually applied to every raw operation. The practical lesson is to name the P-code stage, the selected language, and the state assumptions behind any claimed execution result.

John Toterhi's [Ghidra P-code emulation walkthrough](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb) makes that state requirement concrete by setting up registers, memory, a starting address, and steps in Ghidra's emulator. It is a useful bridge between reading a listing and asking “what would these operations do for this input?” An emulator answers that question for a supplied state and path. Static analysis asks a broader question about many possible states.

## A brief note on HydIR

HydIR uses Ghidra automatically as a frontend and imports **raw** P-code with source bytes, addresses, varnodes, operation order, and register-space information. The raw operations feed its Rust semantics and bounded lift; Ghidra's optional high P-code is kept as separate decompiler evidence. This follows the division above: a concise high-level value is useful for explanation, while the ordered raw effects are what a concrete executor must account for.

For the `TEST` example, the useful HydIR question is specific: given `RDI = 0x48` and `RSI = 0x08`, does the modeled path set `ZF` to zero and fall through at `0x2013d9`? With `RDI = 0x40`, does it take the branch? Both paths were run against the saved fixture. If a necessary memory byte, user operation, or target is unknown, the result reports that source site instead of inventing a continuation. Readers who want the implementation can inspect the [exporter](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/integrations/ghidra/HydIRSnapshot.java) and [P-code model](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/crates/hydir-ir/src/pcode.rs).

P-code is valuable because it makes small effects visible. Once you learn to read a varnode's space and width, follow an output into the next operation, and distinguish instruction translation from decompiler analysis, a mysterious line of C becomes a chain you can inspect. That skill transfers to emulator scripts, slicing, decompiler debugging, and any framework built on Ghidra's frontend.

## Reading list

- [Ghidra's SLEIGH manual](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), [operation reference](https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html), [pseudo operations](https://ghidra.re/ghidra_docs/languages/html/pseudo-ops.html), and [analysis-only operations](https://ghidra.re/ghidra_docs/languages/html/additionalpcode.html): the definitive definitions used throughout this article.
- [Emulating Ghidra's PCode: Why/How](https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb): a worked introduction to seeded P-code emulation.
- [Implementing a brainfuck CPU in Ghidra, part 2](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-2.html): a small SLEIGH example that shows where unique varnodes come from and how to view raw P-code.
- [A Gentle Introduction to Static Analysis with Ghidra Pcode](https://v0iddeck.com/articles/static-analysis-ghidra-pcode) and [using high P-code to detect patterns](https://twevs.github.io/2023/03/10/using-high-p-code-to-detect-patterns-in-decompiler-output.html): practical high-P-code dataflow examples.
- [NCC Group's earlyremoval investigation](https://www.nccgroup.com/research/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/) and [PracticalPCode](https://github.com/kohnakagawa/PracticalPCode): examples of what high-P-code transformation can hide and what it can make tractable.
- [A Formal Semantics for P-Code](https://link.springer.com/chapter/10.1007/978-3-031-25803-9_7): a research treatment of high-P-code semantics.

The concrete `TEST` sequence and operation counts above come from HydIR's [checked-in Ghidra snapshot](https://github.com/Achxy/hydir-2/blob/34dbb5b11d71e43feb10e8e83e87f307b92012eb/tests/fixtures/ghidra_prism_bit_gate_oracle_v2.json), examined at repository revision [`34dbb5b`](https://github.com/Achxy/hydir-2/tree/34dbb5b11d71e43feb10e8e83e87f307b92012eb). The flag-name transcription is editorial; the snapshot retains the exact register and unique-space offsets.
