A binary has no obligation to resemble the source program that produced it. Variables have become registers. An integer comparison has become a subtraction followed by a test of condition flags. A source-level expression may have disappeared into an addressing calculation. Before we can simplify any of that, we need a precise account of what the remaining instructions do.

HydIR makes these questions explicit at several levels. Its native pipeline carries decoded instructions through MachineIR, StateIR, FunctionIR, and CIR before producing C. A separate scalar compatibility path translates a restricted function into LLVM IR. The [architecture guide](/architecture) explains how those paths fit together.

We will begin with a deliberately small example: a maximum function with two 64-bit inputs in RDI and RSI and a result in RAX. That projection lets us derive the arithmetic and branch conditions without carrying an entire machine through every equation. We will then extend the model to partial register writes and uncertain effects. These derivations are specifications and worked arguments; the implementation and its tests supply separate evidence.

## A word has two interpretations

Let $\BV_w$ be the set of words with exactly $w$ bits. We write $u(x)$ for the unsigned integer represented by a word and $s(x)$ for its two's-complement signed interpretation.

$$ {#word-interpretations}
\begin{aligned}
\BV_w &= \{0,1\}^{w}, \qquad M = 2^w,\\
u(x) &= \sum_{i=0}^{w-1} x_i 2^i,\\
s(x) &=
\begin{cases}
u(x), & u(x)<2^{w-1},\\
u(x)-2^w, & u(x)\ge 2^{w-1}.
\end{cases}
\end{aligned}
$$

Neither interpretation changes the bits. For an eight-bit word, `11111111` represents $255$ under $u$ and $-1$ under $s$. Consequently, `11111111` is greater than `00000001` in unsigned order and less than it in signed order.

Addition and subtraction have an especially useful property: their low $w$ result bits agree under either interpretation. We can calculate them in the quotient ring $\mathbb Z/2^w\mathbb Z$:

$$ {#modular-arithmetic}
\begin{aligned}
u(a +_w b) &= \bigl(u(a)+u(b)\bigr)\bmod M,\\
u(a -_w b) &= \bigl(u(a)-u(b)\bigr)\bmod M.
\end{aligned}
$$

This is a ring, generally not a field: the nonzero residue $2$ has no multiplicative inverse modulo $2^w$ when $w>1$. Ordinary algebraic cancellation by a nonzero factor can therefore fail. For example, in eight bits, $2\cdot 0=2\cdot128=0$, although $0\ne128$. Cancellation of an additive term remains valid.

Bitwise operations live alongside that arithmetic. XOR operates independently on each bit; it is not addition modulo $2^w$, because it does not propagate carries. Keeping those two algebras distinct prevents attractive but incorrect simplifications. In four bits, $1\mathbin{\oplus}1=0$, whereas $1+_4 1=2$.

The worked maximum uses $w=64$. HydIR's native semantics also handle narrower operations; the width must come from the decoded instruction. Our eight-bit examples make wraparound visible without changing the formulas. The [SMT-LIB bitvector theory](https://smt-lib.org/theories-FixedSizeBitVectors.shtml) provides the standard vocabulary for expressing fixed-width operations to a solver.

## The state we choose to model

A full x86 machine state includes memory, many registers, exceptional behavior, and environmental interactions. For the arithmetic examples, choose this smaller state:

$$ {#scalar-state}
\begin{aligned}
\sigma &= (p,\rho,\varphi),\\
\rho &: \mathcal R \longrightarrow \BV_{64},
&\mathcal R &= \{\mathrm{RAX,RDI,RSI,RDX,RCX}\},\\
\varphi &: \mathcal F \longrightarrow \{0,1\},
&\mathcal F &= \{\mathrm{ZF,SF,OF,CF}\}.
\end{aligned}
$$

Here $p$ is the current instruction address, $\rho$ maps the selected registers to words, and $\varphi$ maps four condition flags to Boolean values. Our two-input example initially supplies RDI and RSI. A read of another field needs either an explicit input assumption or a preceding definition.

This is a teaching model, not an inventory of HydIR's current state. The scalar backend tracks fourteen general-purpose registers, four flags, and eight proved stack slots, with six physical SysV integer argument registers at entry. Native StateIR tracks register, flag, memory-region, and control components. Restricting attention to five registers is justified for these examples by their reads and writes, not by claiming the rest of the architecture does not exist.

A supported instruction at address $p$ supplies a state transformer $T_p$. A register-to-register move updates one coordinate and leaves the others unchanged:

$$ {#move-semantics}
\frac{\operatorname{decode}(p)=\operatorname{mov}\ d,s}
{(p,\rho,\varphi)\longrightarrow
(p+\ell_p,\rho[d\mapsto\rho(s)],\varphi)}.
$$

The notation $\rho[d\mapsto v]$ means “the same register map, except that $d$ now maps to $v$.” The instruction length is $\ell_p$. Notice that the flags are preserved. Translating a move using an LLVM arithmetic expression does not license changing the modeled x86 flags.

Likewise, a supported `lea` is arithmetic on register values:

$$ {#lea-semantics}
\rho'(d)=
\rho(b)+_{64}\bigl(k\cdot_{64}\rho(i)\bigr)+_{64}\delta,
\qquad \varphi'=\varphi.
$$

An absent base or index contributes zero. The implementation restricts which forms of `lea` it accepts; this equation is not a model of arbitrary x86 addressing. In particular, calculating an address does not itself read the memory at that address.

There is one important boundary convention. A hardware `ret` reads a return address from the stack. In this scalar model, `ret` ends the selected function and exposes RAX to the host caller. Relating that boundary to a real execution requires the calling convention and a valid call/return context. RSP and guest stack memory are not silently being simulated.

## Carry and overflow answer different questions

Suppose an addition computes $r=a+_w b$. For this section, arithmetic inequalities use unsigned integer representatives unless $s$ appears explicitly. Write $A=\msb(a)$, $B=\msb(b)$, and $R=\msb(r)$ for the sign bits.

The four flags used by our branch examples follow from the result and the operands:

$$ {#addition-flags}
\begin{aligned}
\mathrm{ZF} &= [u(r)=0],\\
\mathrm{SF} &= R,\\
\mathrm{CF}_{+} &= [u(a)+u(b)\ge M]=[u(r)<u(a)],\\
\mathrm{OF}_{+} &= \neg(A\oplus B)\land(A\oplus R).
\end{aligned}
$$

Brackets $[P]$ denote the Boolean value of proposition $P$. The carry identity is worth proving. If $u(a)+u(b)<M$, then $u(r)=u(a)+u(b)\ge u(a)$. If the sum crosses $M$, then $u(r)=u(a)+u(b)-M<u(a)$ because $u(b)<M$. That gives a carry test using only a same-width unsigned comparison.

Overflow asks whether the *signed* mathematical sum fits. Adding operands of opposite signs cannot exceed the signed range. For equal signs, overflow occurs exactly when the result's sign differs from the operands' sign. That is what the Boolean formula says.

The distinction is visible in eight bits:

| Operation | Result word | Unsigned result | Signed result | CF | OF |
| --- | --- | --- | --- | --- | --- |
| $127+1$ | `10000000` | $128$ | $-128$ | $0$ | $1$ |
| $255+1$ | `00000000` | $0$ | $0$ | $1$ | $0$ |
| $128+128$ | `00000000` | $0$ | $0$ | $1$ | $1$ |

The last row represents $-128+(-128)$ under the signed interpretation. One result can therefore overflow both interpretations. A lifter that stores only “the operation overflowed” has already discarded information needed by later branches.

HydIR's [`emit_flags` implementation](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-backend/src/cfg.rs) uses precisely this shape: signed comparisons extract sign information, Boolean operations construct OF, and an unsigned comparison constructs CF. The [Intel instruction manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) are the architectural reference for the underlying ADD, SUB, CMP, TEST, and conditional-jump behavior.

<section class="lab" id="flags-lab" hidden aria-labelledby="flags-lab-title">
<h3 id="flags-lab-title">Try the flag equations in eight bits</h3>
<p>Enter unsigned bit patterns from 0 to 255. The same result is interpreted both ways below.</p>
<div class="lab-controls">
<label>Operand a<input id="flag-a" type="number" min="0" max="255" step="1" value="127"></label>
<label>Operation<select id="flag-op"><option value="add">Add</option><option value="sub">Subtract</option></select></label>
<label>Operand b<input id="flag-b" type="number" min="0" max="255" step="1" value="1"></label>
</div>
<div class="lab-presets"><button type="button" data-flag-preset="127,1,add">127 + 1</button><button type="button" data-flag-preset="255,1,add">255 + 1</button><button type="button" data-flag-preset="128,1,sub">128 − 1</button></div>
<div role="status" aria-live="polite" aria-atomic="true">
<p class="lab-result" id="flag-bits">10000000</p>
<p id="flag-interpretation">Unsigned 128 · Signed −128</p>
<dl class="flag-row"><div><dt>Carry / borrow</dt><dd id="flag-cf">0</dd></div><div><dt>Overflow</dt><dd id="flag-of">1</dd></div><div><dt>Zero</dt><dd id="flag-zf">0</dd></div><div><dt>Sign</dt><dd id="flag-sf">1</dd></div></dl>
<p id="flag-explanation">127 + 1 = 128 is outside the signed eight-bit range.</p>
</div>
</section>

## Recovering a comparison from subtraction

`cmp a, b` in Intel operand order computes the flags of $a-b$ without storing the difference. The repository's assembly uses AT&T syntax, where `cmpq %rsi, %rdi` means RDI minus RSI. Reversing that operand order reverses the meaning of an unsigned branch.

For $r=a-_w b$, the corresponding formulas are:

$$ {#subtraction-flags}
\begin{aligned}
\mathrm{ZF} &= [u(r)=0], \qquad \mathrm{SF}=R,\\
\mathrm{CF}_{-} &= [u(a)<u(b)],\\
\mathrm{OF}_{-} &= (A\oplus B)\land(A\oplus R).
\end{aligned}
$$

Subtraction sets CF when an unsigned borrow is required. Signed overflow requires operands of different signs and a result whose sign differs from the left operand. The machine does not know whether the programmer intended an unsigned or signed comparison; it computes enough information for either.

After a comparison, unsigned conditions are immediate. Signed conditions require correcting the sign bit for overflow:

$$ {#branch-predicates}
\begin{aligned}
u(a)<u(b) &\iff \mathrm{CF},\\
u(a)\ge u(b) &\iff \neg\mathrm{CF},\\
s(a)<s(b) &\iff \mathrm{SF}\oplus\mathrm{OF},\\
s(a)\ge s(b) &\iff \neg(\mathrm{SF}\oplus\mathrm{OF}).
\end{aligned}
$$

Why does XOR make the signed test work? If $A=B$, the operands have the same sign, subtraction cannot overflow, and the result's sign answers the comparison. If $A\ne B$, the left operand is less exactly when $A=1$. In that case OF is $A\oplus R$, so:

$$ {#signed-comparison-proof}
\mathrm{SF}\oplus\mathrm{OF}
=R\oplus(A\oplus R)
=A.
$$

That is the entire correction. It is not a heuristic about “negative-looking” results.

For example, use the eight-bit patterns $a=128$ and $b=1$. Signed, the desired comparison is $-128<1$. The wrapped subtraction yields $r=127$, so SF is zero; testing SF alone gives the wrong answer. OF is one, and $\mathrm{SF}\oplus\mathrm{OF}=1$ restores it.

The remaining common predicates compose these same bits:

| Branch after CMP | Predicate |
| --- | --- |
| `je` / `jne` | $\mathrm{ZF}$ / $\neg\mathrm{ZF}$ |
| `ja` / `jbe` | $\neg\mathrm{CF}\land\neg\mathrm{ZF}$ / $\mathrm{CF}\lor\mathrm{ZF}$ |
| `jg` / `jle` | $\neg\mathrm{ZF}\land\neg(\mathrm{SF}\oplus\mathrm{OF})$ / $\mathrm{ZF}\lor(\mathrm{SF}\oplus\mathrm{OF})$ |

These interpretations depend on which instruction last defined the flags. After `test`, HydIR computes ZF and SF from a bitwise AND and clears CF and OF. After `mov` or `lea`, the old flags remain. A branch mnemonic alone does not identify a comparison between two source variables.

## Five instructions become one function

The repository's [unsigned-maximum fixture](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/tests/fixtures/max2.S) contains this instruction sequence:

~~~asm
movq %rdi, %rax
cmpq %rsi, %rdi
jae  .Ldone
movq %rsi, %rax
.Ldone:
ret
~~~

Let the input words be $a$ in RDI and $b$ in RSI. The first move establishes the provisional return value $a$. CMP constructs CF as $[u(a)<u(b)]$. JAE takes the branch when CF is false. The other path overwrites RAX with $b$.

$$ {#max-transfer}
\begin{aligned}
P_{\mathrm{take}}(a,b) &= [u(a)\ge u(b)],\\
P_{\mathrm{fall}}(a,b) &= [u(a)<u(b)],\\
F(a,b) &=
\begin{cases}
a, & P_{\mathrm{take}}(a,b),\\
b, & P_{\mathrm{fall}}(a,b).
\end{cases}
\end{aligned}
$$

The predicates are mutually exclusive and exhaustive, so the return value is defined for every pair of input words. This is a transfer function for the selected function boundary. It does not expose the internal value of every flag, because the interface observes RAX.

The final expression can be written as an if-then-else term:

$$ {#max-ite}
F(a,b)=
\operatorname{ite}\!\left(u(a)\ge u(b),\,a,\,b\right).
$$

Replacing JAE with JGE produces the [signed-maximum fixture](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/tests/fixtures/signed_max2.S). Nothing about the argument bit width changes. For $a=2^{64}-1$ and $b=1$, unsigned maximum returns $a$, whereas signed maximum returns $b$. Calling both simply `max` would lose part of their semantics.

This example also explains why deriving behavior is different from recovering original source. Many source programs can implement the same $F$. The bytes constrain the behavior, but they do not identify the original variable names, type declarations, or expression spelling.

## Keeping the arithmetic intact in LLVM and C

HydIR's scalar LLVM path emits ordinary `i64` addition and subtraction without `nsw` or `nuw` promises. In LLVM 14, overflow under one of those promises produces poison; ordinary integer addition instead returns the modular result. That semantic distinction is specified in the [LLVM language reference](https://releases.llvm.org/14.0.0/docs/LangRef.html#add-instruction).

Here is the concrete obligation. For all input words, the generated operation must agree with the machine operation:

$$ {#arithmetic-obligation}
\forall a,b\in\BV_{64},\quad
u\!\left(\operatorname{LLVMadd}(a,b)\right)
=\bigl(u(a)+u(b)\bigr)\bmod 2^{64}.
$$

An extra no-wrap promise is an extra precondition. The binary has not supplied that precondition merely by using ADD. An optimizer can legally exploit the promise, so a mistranslation may become observable only after optimization.

The scalar [LLVM-to-C emitter](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-c/src/lib.rs) carries register values in `uint64_t` variables. Signed comparisons are particularly interesting: its `expression` function orders unsigned words after flipping their sign bits, rather than depending on an out-of-range conversion to a signed C type.

Define the bias map $\beta$:

$$ {#sign-bias}
\beta(x)=u(x)\mathbin{\oplus}2^{w-1}.
$$

For a word in the lower half of the unsigned range, flipping the high bit adds $2^{w-1}$. For a word in the upper half, it subtracts $2^{w-1}$. In both cases:

$$ {#bias-identity}
\beta(x)=s(x)+2^{w-1}.
$$

The right-hand side is an ordinary integer in $[0,2^w-1]$. Adding the same constant preserves order, yielding:

$$ {#bias-order}
\boxed{\quad
s(a)<s(b)\iff \beta(a)<\beta(b).
\quad}
$$

At width 64, the C expression becomes:

~~~c
(a ^ UINT64_C(9223372036854775808))
  < (b ^ UINT64_C(9223372036854775808))
~~~

The formula is short because the proof did the work. It also avoids accidentally performing signed overflowing arithmetic while trying to emulate a machine that wraps.

For flag values represented in C as 64-bit containers, this emitter masks Boolean binary results with one. The storage type is wider than the modeled value; the low-bit invariant keeps those meanings aligned.

## A narrow write changes a wider state

Operand width is more than a choice of modulus. On x86-64, writing EAX clears the upper half of RAX. Writing AX preserves the other 48 bits. Let $x$ be the old RAX value and $r_k$ a $k$-bit result. The two state updates differ:

$$ {#partial-register-writes}
\begin{aligned}
\operatorname{write}_{\mathrm{EAX}}(x,r_{32})
  &= \operatorname{zext}_{32\to64}(r_{32}),\\
\operatorname{write}_{\mathrm{AX}}(x,r_{16})
  &= \left(x\mathbin{\&}\mathtt{0xffffffffffff0000}\right)
     \mathbin{|}\operatorname{zext}_{16\to64}(r_{16}).
\end{aligned}
$$

The second operation depends on the old full register; the first does not. Consequently, an SSA representation of a partial write may need the previous register version as an input even when the instruction seems to overwrite its destination. HydIR's native lowering preserves these width and merge rules in its register effects and C operations. The [native decompiler documentation](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/docs/NATIVE_DECOMPILER.md) describes the supported forms.

Flags introduce another distinction. An instruction can preserve a flag, define it, or leave its architectural value undefined. Those cases cannot share one translation. If a flag becomes undefined, retaining its old SSA value would assert a relation the architecture does not guarantee.

One mathematical model allows a set of successor states rather than one successor:

$$ {#relational-semantics}
T_p:\Sigma\longrightarrow\mathcal P(\Sigma),
\qquad
\varphi'(f)\in\{0,1\}
\quad\text{when }f\text{ becomes undefined}.
$$

This is nondeterminism in a specification, not a claim that hardware flips a random coin. An opaque instruction may admit many possible state changes constrained by its recorded footprint. With incomplete semantic knowledge, an analysis should preserve those possibilities instead of inventing one convenient result. A desired conservative condition is:

$$ {#effect-overapproximation}
\operatorname{Post}_{\mathrm{machine}}(S)
\subseteq
\gamma\!\left(\operatorname{Post}_{\mathrm{abstract}}(\alpha(S))\right).
$$

Here $\alpha$ maps concrete states to an abstract description and $\gamma$ gives that description its concrete meaning. The inclusion says the analysis must contain every behavior it claims to cover. It does not establish exact equality, and it is an obligation for an abstraction, not a proof already supplied for all HydIR operations.

Native StateIR records undefined flags as new component outputs. Native C uses an explicit `hydir_undefined_flag` helper, and unsupported operations retain opaque effects. Those representations expose uncertainty; their presence is not evidence that the emitted C is a complete executable model of the original instruction.

## What a proof of a lift would require

Return to the exact scalar LLVM experiment. Let $L$ denote that lifter. It is best modeled as a partial operation: some byte sequences and assumptions produce an IR artifact, while others produce a diagnostic.

$$ {#partial-lifter}
L:(\text{bytes},\text{extent},\text{ABI})
\rightharpoonup \text{LLVM IR}.
$$

The partial arrow refers to translation being unsupported, not to a translated function necessarily failing to terminate. A successfully recovered loop still needs its own termination argument if the claim is that it always returns.

For a returning scalar computation, define the observable behavior to be its returned word. If $B$ is a selected binary function and $I=L(B)$, the intended equality is:

$$ {#behavioral-contract}
\forall a,b\in\BV_{64},\quad
\Obs(B,a,b)=\Obs(I,a,b),
$$

subject to the stated ABI, valid function invocation, supported semantics, and whatever termination conditions the claim requires. Equality of return values alone says nothing about execution time, side channels, arbitrary memory effects, or whole-executable behavior.

A proof normally needs a relation $\mathcal R$ between source and target states. At each corresponding block boundary, modeled registers and flags must denote the same values. One source instruction may require several LLVM instructions, so the target takes one or more steps:

$$ {#simulation-obligation}
\frac{
\mathcal R(\sigma,\tau)
\qquad \sigma\longrightarrow_B\sigma'
}{
\exists\tau'.\
\tau\longrightarrow_I^{+}\tau'
\ \land\ \mathcal R(\sigma',\tau')
}.
$$

The obligations are connected. Establish $\mathcal R$ at entry using the ABI. Prove the local step condition for each supported operation. Show that branch destinations correspond. Show that the relation at a return implies equal observations. Then induction over a finite source trace composes the local arguments.

For loops and full behavioral equivalence, termination, divergence, and the direction of simulation need explicit treatment. A forward simulation of terminating traces is not automatically a proof of every stronger equivalence notion. HydIR does not currently ship a machine-checked proof of this entire chain. Writing the obligation down makes the missing work identifiable.

Refusal is useful here, but refusal alone is not a soundness theorem. Rejecting an unsupported addressing form or an unjustified read reduces the accepted domain; each accepted operation still needs justification. The native pipeline takes a different approach where possible: it preserves unsupported semantics as opaque effects and marks the result accordingly. A partial native result does not inherit the exact scalar contract merely because it can be printed as C.

## Symbolic paths and a small solver check

A symbolic execution replaces concrete inputs with variables and accumulates conditions along a path. If the selected branch predicates on path $\pi$ are $c_1,\ldots,c_k$, with each negated when taking its false edge, then:

$$ {#path-condition}
P_\pi(a,b)=\bigwedge_{j=1}^{k}c_j(a,b).
$$

If that path returns expression $E_\pi(a,b)$, a desired result $y$ can be sought by asking whether this formula is satisfiable:

$$ {#reachability-query}
\exists a,b\in\BV_{64}:\quad
P_\pi(a,b)\land E_\pi(a,b)=y.
$$

A satisfying assignment is a witness for the modeled path. It should be replayed against the intended semantics; missing environmental assumptions are not repaired by a solver returning `sat`.

HydIR's optional [Triton bridge](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/scripts/triton_bridge.py) explores bounded direct paths, reconstructs a context per path, and assembles textual ITE expressions for return values. In this checkout, it limits code to 4,096 bytes, completed paths to 64, and path length to 1,024 instructions; revisiting an instruction on a path is rejected. Those are limits on its accepted exploration, not a general loop-proof mechanism.

Merging path expressions also carries an obligation. The returned cases must cover the claimed domain. An ITE chain with a final unguarded “else” is justified only when that fallback covers the remaining domain or the result is explicitly restricted to explored paths. We must distinguish the expression's syntax from a claim about path coverage.

For a smaller, self-contained proof task, we can ask a bitvector solver to find a counterexample to the signed-less identity derived earlier:

~~~smt2
(set-logic QF_BV)
(declare-fun a () (_ BitVec 64))
(declare-fun b () (_ BitVec 64))
(define-fun r () (_ BitVec 64) (bvsub a b))
(define-fun sign ((x (_ BitVec 64))) Bool
  (= ((_ extract 63 63) x) #b1))
(define-fun overflow () Bool
  (and (xor (sign a) (sign b))
       (xor (sign a) (sign r))))
(assert
  (not (= (xor (sign r) overflow) (bvslt a b))))
(check-sat)
~~~

The [downloadable query](/examples/signed-branch.smt2) asks whether *any* 64-bit operands violate that particular algebraic identity. Z3 4.16.0 returned `unsat` for this query, consistent with the two-case proof above. The [six accompanying identity checks](/examples/arithmetic-identities.smt2) also returned `unsat`: they cover addition carry and overflow, subtraction borrow and overflow, signed comparison, and sign-bit biasing.

These are checks of explicitly encoded formulas. They do not invoke HydIR or prove equivalence of its emitted LLVM module or x86 decoder. To reproduce them from the blog directory:

~~~sh
z3 examples/signed-branch.smt2
z3 examples/arithmetic-identities.smt2
~~~

## What finite tests can tell us

The scalar validation scripts compare native fixtures with compiled LLVM and C outputs. The documented demo configuration uses 1,008 input pairs for each function and output path. Those inputs can reveal incorrect arithmetic, branch direction, or ABI handling. They do not enumerate the input space:

$$ {#input-space}
\left|\BV_{64}\times\BV_{64}\right|=2^{128}.
$$

To see why “many passing tests” needs a sampling model, suppose hypothetically that each test were an independent uniform sample and a bug affected a fraction $p$ of the input domain. The probability of missing it after $n$ tests would be:

$$ {#sampling-limit}
\Pr[\text{no counterexample in }n\text{ samples}]
=(1-p)^n.
$$

For tiny $p$, this can remain close to one despite thousands of tests. The actual mixture of directed and generated cases should not be assigned this probability without establishing those assumptions.

The equations suggest better test selection. Exercise zero, the unsigned maximum, the signed boundary, equal operands, opposite-sign operands, wraparound, and both branch outcomes. Use the signed and unsigned maximum fixtures together. Tests become more informative when they target the places where the mathematical interpretations separate.

There are also different questions at different stages. An IR verifier checks the shape of LLVM IR. Differential execution checks selected observations on selected inputs. The standalone SMT query checks an identity in its encoded theory. A semantic proof would connect the whole accepted translation to the machine model. Keeping those results distinct is part of understanding the system.

## Reading the implementation

Implementation descriptions were checked against revision `b00835d`. The source links below are pinned to that revision. The small arithmetic state is an explicit projection; the native and compatibility paths are identified separately.

- [`cfg.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-backend/src/cfg.rs): `Field` defines the scalar backend's fields; `emit_flags` and `condition_name` implement the arithmetic and branch formulas. Operation classification is shared through `hydir-semantics`.
- [`hydir-decompile/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-decompile/src/lib.rs): native lowering, register-width effects, and component SSA, including undefined-flag outputs.
- [`hydir-c/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-c/src/lib.rs): `expression` uses modular unsigned operations, sign-bit biasing, and low-bit masks.
- [`max2.S`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/tests/fixtures/max2.S) and [`signed_max2.S`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/tests/fixtures/signed_max2.S): the paired worked examples.
- [`demo-local.sh`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/scripts/demo-local.sh) and [`demo-corpus.sh`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/scripts/demo-corpus.sh): the native comparison procedure and fixture corpus.

The next question is structural: how does a collection of state transformers become legal SSA when branches merge or loop back? [The companion article](/articles/graphs-to-code) follows the graph algorithms that make those incoming values explicit.
