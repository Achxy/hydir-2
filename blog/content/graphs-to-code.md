Suppose we already know how each supported machine instruction changes registers and flags. That still does not give us a compiler. A register can be assigned on one branch and left untouched on another. A loop can carry yesterday's value into today's iteration. A return may be reachable through a path on which its result was never initialized.

The missing structure is a graph, and the missing reasoning is dataflow analysis. HydIR's native pipeline expresses those ideas through MachineIR, StateIR, FunctionIR, and CIR. Its scalar compatibility backend offers a particularly small worked example: each recovered instruction becomes an LLVM block, with incoming machine values represented by explicit phi nodes.

We will use that scalar example to derive initialization and SSA, then connect the construction to the native pipeline's memory effects and structured C. The [mathematics companion](/articles/bitvectors-to-behavior) derives the arithmetic carried by the graph. Here the central question is which values are available along which edges, and how to preserve them when the representation changes.

## Recovery is a claim about a region

A symbol can provide an entry address $a$ and a byte extent $n$. Alternatively, the analyst can supply both. These define a region:

$$ {#selected-region}
\Omega=[a,a+n),\qquad 1\le n\le4096.
$$

The 4,096-byte bound belongs to the scalar compatibility lifter. Native discovery has different limits, including a 64 KiB per-function byte bound in the inspected revision. An extent is a recovery boundary, not evidence that every byte inside it belongs to an executed instruction or that the selected function has a particular prototype.

On x86, instructions have variable lengths. Decoding at the wrong offset can produce a plausible but different instruction stream. A lifter therefore needs more than a list of mnemonics: it must commit to instruction boundaries and explain how each boundary was reached.

The scalar backend's [`recover_bounded` function](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-backend/src/cfg.rs), used by `recover`, begins with the selected entry in a queue. It decodes an instruction, classifies its semantics, assigns ownership of its bytes, and queues its successors. For the call-free direct-control-flow example:

$$ {#successor-function}
\operatorname{Succ}(p)=
\begin{cases}
\varnothing, & \operatorname{ret},\\
\{t\}, & \operatorname{jmp}\ t,\\
\{t,p+\ell_p\}, & \operatorname{jcc}\ t,\\
\{p+\ell_p\}, & \text{other supported instruction}.
\end{cases}
$$

Every successor must lie in $\Omega$. The ownership map assigns each decoded byte to exactly one instruction start. If the intervals of two distinct recovered instructions overlap, recovery fails:

$$ {#ownership-invariant}
p\ne q
\ \Longrightarrow\
[p,p+\ell_p)\cap[q,q+\ell_q)=\varnothing.
$$

This rejects a branch into the middle of an already recovered instruction, regardless of which decoding is encountered first. Indirect edges cannot be resolved by this successor rule, so the scalar path rejects them. The native pipeline can recover some bounded indirect target sets; the [jump-table article](/articles/recovering-jump-tables) explains why it also preserves an unresolved default.

The result is a directed graph $G=(V,E)$ with instruction addresses as vertices. “Reachable” here means reachable by traversing recovered edges. The pass follows both conditional successors without first proving that their branch predicates are satisfiable. It can therefore include paths that no input will actually take.

That distinction will matter later. A structurally conservative graph can cause an initialization check to reject a function whose unsafe-looking path is infeasible. Rejecting such a case is a precision limit, not permission to silently remove the path.

## The maximum fixture as a graph

Consider the same five-instruction unsigned maximum used in the [introductory walkthrough](/articles/max2):

~~~asm
movq %rdi, %rax
cmpq %rsi, %rdi
jae  .Ldone
movq %rsi, %rax
.Ldone:
ret
~~~

Let us name its instruction nodes $m,c,j,u,r$: initial move, comparison, jump, update, and return. The graph is:

$$ {#max-graph}
\begin{aligned}
V&=\{m,c,j,u,r\},\\
E&=\{(m,c),(c,j),(j,r),(j,u),(u,r)\}.
\end{aligned}
$$

<figure>
<div class="diagram">
<svg viewBox="0 0 700 425" role="img" aria-labelledby="cfg-title cfg-description">
<title id="cfg-title">The five instruction nodes of unsigned maximum</title>
<desc id="cfg-description">Move a into RAX, compare a and b, then branch. The taken path goes directly to return when a is at least b. The other path moves b into RAX before joining the return.</desc>
<defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0 0 L7 3.5 L0 7" class="arrow"/></marker></defs>
<g class="nodes" stroke-width="1.2">
<rect x="218" y="16" width="264" height="48"/><rect x="218" y="100" width="264" height="48"/>
<rect x="218" y="184" width="264" height="48"/><rect x="28" y="280" width="245" height="48"/>
<rect x="218" y="365" width="264" height="48"/>
</g>
<g font-size="15" text-anchor="middle">
<text x="350" y="46">m: RAX ← a</text><text x="350" y="130">c: flags ← cmp(a, b)</text>
<text x="350" y="214">j: branch on ¬CF</text><text x="150" y="310">u: RAX ← b</text>
<text x="350" y="395">r: return RAX</text>
</g>
<g fill="none" class="edges" stroke-width="1.5" marker-end="url(#arrow)">
<path d="M350 64 V97"/><path d="M350 148 V181"/><path d="M282 232 L151 277"/>
<path d="M150 328 L275 362"/><path d="M420 232 L567 282 V335 L427 362"/>
</g>
<g font-size="12" class="annotation"><text x="35" y="251">fallthrough: a &lt; b</text><text x="486" y="242">taken: a ≥ b</text></g>
</svg>
</div>
<figcaption>Five machine instructions, five graph nodes, five edges. The return has two predecessors carrying different definitions of RAX.</figcaption>
</figure>

A conventional compiler would often group consecutive instructions into larger basic blocks. HydIR's scalar LLVM backend instead creates one block per instruction. This produces more labels and more phi nodes, but preserves a simple correspondence between an address, its state transformer, and its incoming state. Native MachineIR uses its own block representation; one LLVM block per instruction is not a rule for every HydIR pipeline.

The return does not need to remember why a predecessor was selected. It needs the value of RAX from the predecessor that was actually executed. Before generating that selection, however, the lifter must establish that a value exists on every incoming path.

## Definite initialization is a must analysis

Let $\mathcal U$ be the scalar backend's field universe: fourteen registers, four flags, and eight stack slots. At each instruction node $v$, define $D_v^{\mathrm{in}}$ and $D_v^{\mathrm{out}}$ to be sets of fields known to be initialized before and after executing that instruction.

Its physical SysV entry model supplies six integer argument registers:

$$ {#initial-fields}
\mathcal I=\{\mathrm{RDI},\mathrm{RSI},\mathrm{RDX},
\mathrm{RCX},\mathrm{R8},\mathrm{R9}\}\subset\mathcal U.
$$

The maximum example uses only the first two. Let $\operatorname{Def}(v)$ contain fields established by the instruction and $\operatorname{Kill}(v)$ contain fields whose old values cannot be carried through. The transfer function is:

$$ {#definition-transfer}
D_v^{\mathrm{out}}
=\left(D_v^{\mathrm{in}}\setminus\operatorname{Kill}(v)\right)
\cup\operatorname{Def}(v).
$$

Ordinary moves have an empty kill set. An allowed direct call kills caller-clobbered fields and establishes its modeled return value in RAX. Carrying the old flags through that call would create false guarantees. Stack slots enter the same analysis only after a separate stack-frame proof has identified their accesses.

The interesting operation is the join. To be definitely initialized at $v$, a field must be initialized on *every* incoming edge:

$$ {#must-join}
\begin{aligned}
D_v^{\mathrm{in}}
&=B_v\cap
\bigcap_{p\in\operatorname{Pred}(v)}D_p^{\mathrm{out}},
\\[0.5em]
B_v&=
\begin{cases}
\mathcal I,&v=\text{entry},\\
\mathcal U,&\text{otherwise}.
\end{cases}
\end{aligned}
$$

The intersection over an empty predecessor set is $\mathcal U$. Thus the external entry contributes $\mathcal I$ even when the entry node has a loop backedge. Treating the function entry as “whatever the backedge provides” would wrongly allow a loop to invent its own initial values.

For unsigned maximum, the initial move defines RAX. CMP defines all four flags. JAE preserves the fields, and the optional second move redefines RAX. Both paths reaching the return therefore include RAX in their outgoing sets.

Now remove the first move. The update path still defines RAX, but the direct branch to the return does not:

$$ {#bad-return}
\mathrm{RAX}\in D_u^{\mathrm{out}},
\quad
\mathrm{RAX}\notin D_j^{\mathrm{out}}
\quad\Longrightarrow\quad
\mathrm{RAX}\notin D_r^{\mathrm{in}}.
$$

The return must be rejected. Using a union at that join would establish only that RAX is initialized on *some* path, exactly the wrong claim.

Once the fixed point is computed, HydIR checks each instruction's declared reads:

$$ {#read-obligation}
\boxed{\quad
\forall v\in V,\qquad
\operatorname{Read}(v)\subseteq D_v^{\mathrm{in}}.
\quad}
$$

The implementation represents field sets as bit masks, so this becomes `reads & !incoming == 0`. Read and write masks come from the shared instruction effects; the graph layer adds stack-slot and allowed-call dependencies. Getting those masks right is part of the semantic model, not a consequence of the fixed-point algorithm.

## Why loops need a fixed point

On an acyclic graph, a topological traversal can propagate information forward once. A loop destroys that order: a node's incoming set depends on a predecessor whose incoming set depends on the node itself.

Collect all incoming and outgoing sets into a product domain:

$$ {#must-domain}
\mathcal D
=\prod_{v\in V}
\left(\mathcal P(\mathcal U)\times\mathcal P(\mathcal U)\right),
$$

ordered componentwise by set inclusion. Intersection, removal of a fixed kill set, and union with a fixed definition set are monotone. The equations define a monotone function $F:\mathcal D\to\mathcal D$.

HydIR initializes the sets to $\mathcal U$ and repeatedly scans the graph, applying the equations until nothing changes. In mathematical notation, a simultaneous version of the same iteration is:

$$ {#descending-iteration}
D^{(0)}=\top,\qquad
D^{(k+1)}=F(D^{(k)}),\qquad
D^{(0)}\supseteq D^{(1)}\supseteq\cdots.
$$

The implementation updates in place rather than taking a fresh simultaneous snapshot. Monotonicity and repeated complete scans still take the finite descending process to the greatest fixed point of these equations.

There are 26 field bits in each incoming and outgoing set. Across the stored sets, at most $2|\mathcal U||V|=52|V|$ bit removals are possible. This bounds strict state changes, not the total cost of repeatedly scanning predecessors. It explains termination of this analysis without a timeout heuristic.

The optimistic initialization is safe because no reads are approved until convergence. Suppose a loop body defines RAX but the path from entry to its header does not. At the header $h$, with external predecessor $e$ and backedge predecessor $b$:

$$ {#loop-initialization}
D_h^{\mathrm{in}}
=D_e^{\mathrm{out}}\cap D_b^{\mathrm{out}}
\subseteq D_e^{\mathrm{out}}.
$$

A field missing from the first entry remains missing at the header. Having a value on later iterations cannot justify its first read.

The fixed point describes all graph paths under these transfer rules. It is not a path-feasibility solver. More precise reasoning could prove some edges infeasible, but that would introduce another analysis with its own correctness obligations.

## Making machine state explicit in SSA

Static single assignment form gives every value a unique definition. Registers do not naturally satisfy that property: RAX is repeatedly overwritten. The lifter resolves this by creating a separate SSA name for each modeled field at each relevant block boundary.

For a field $f$ at node $v$, use $x_{v,f}$ for the incoming value and $y_{v,f}$ for the outgoing value. For $f\in D_v^{\mathrm{out}}$, the outgoing name is either a new instruction result or a surviving incoming value:

$$ {#ssa-transfer}
y_{v,f}=
\begin{cases}
T_{v,f}(x_{v,\cdot}),&f\in\operatorname{Def}(v),\\
x_{v,f},&f\in D_v^{\mathrm{in}}\setminus
  \left(\operatorname{Kill}(v)\cup\operatorname{Def}(v)\right).
\end{cases}
$$

The entry value is selected from predecessor outputs. If $f\in D_v^{\mathrm{in}}$, HydIR emits the corresponding phi:

$$ {#ssa-join}
x_{v,f}
=\phi\!\left(
[y_{p_1,f},p_1],\ldots,[y_{p_k,f},p_k]
\right).
$$

At the entry block, an artificial `prologue` predecessor supplies the six physical arguments; the maximum fixture consumes the first two. Registers and stack slots use LLVM `i64`; flags use `i1`. A field that failed the initialization condition receives no invented input value.

Phi is an edge-indexed selection. When control arrives from predecessor $p_i$, the selected value is $y_{p_i,f}$. It is not a runtime function that evaluates all alternatives, and it does not mean “pick whichever operand is defined.” LLVM also requires phi instructions to precede ordinary instructions in a block; incoming uses belong to their predecessor edges. See the [LLVM phi specification](https://releases.llvm.org/14.0.0/docs/LangRef.html#phi-instruction).

For the maximum fixture, the essential return block has this shape. Names are shortened for explanation:

~~~llvm
done:
  %answer = phi i64 [ %a, %branch ], [ %b, %update ]
  ret i64 %answer
~~~

The complete raw lift contains many more phis, including single-predecessor phis and fields not ultimately used by the return. It carries the initialized machine state explicitly instead of trying to minimize SSA during construction.

This separates two obligations. The front end produces a traceable representation of state flow. Later passes may simplify redundant values and blocks, provided they preserve the IR's semantics.

## Dominance explains the conventional alternative

Why do most compiler discussions introduce dominance when describing SSA? A definition must be available wherever its value is used. A node $d$ dominates $v$ if every path from entry to $v$ passes through $d$:

$$ {#dominance}
d\operatorname{dom}v
\iff
\forall\pi:\operatorname{entry}\leadsto v,\quad d\in\pi.
$$

At a join reached from different definitions, neither definition necessarily dominates the join. A phi introduces a new definition there, with its operands used on the incoming edges.

The dominance frontier records the boundary where a node's dominance stops being strict:

$$ {#dominance-frontier}
\operatorname{DF}(d)=
\left\{
v\ \middle|\
\begin{aligned}
&\exists p\in\operatorname{Pred}(v):d\operatorname{dom}p,\\
&\neg(d\operatorname{sdom}v)
\end{aligned}
\right\}.
$$

Strict dominance means domination with unequal nodes. This formulation permits a loop header to occur in its own dominance frontier, which is exactly where a loop-carried phi may be needed.

The classic [Cytron et al. SSA construction](https://research.ibm.com/publications/efficiently-computing-static-single-assignment-form-and-the-control-dependence-graph) uses dominance-frontier reasoning to place phis. Liveness information can further avoid phis whose results cannot matter.

HydIR's scalar lifter does not implement that placement algorithm. It emits a phi for every definitely initialized field at every recovered instruction block. Comparing these strategies explains the raw IR's size without pretending that the implementation contains a dominance-frontier pass.

For a small, bounded lifter, the explicit construction has a useful audit property: the naming convention links a field's input and output to an instruction address. The tradeoff is redundant structure that later passes may remove.

## Native SSA also versions memory and uncertainty

The native pipeline generalizes the state-flow idea without routing C generation through LLVM:

$$ {#native-pipeline}
\begin{aligned}
\text{MachineIR}&\longrightarrow\text{StateIR}
  \longrightarrow\text{FunctionIR}\\
&\longrightarrow\text{CIR}\longrightarrow\text{C}.
\end{aligned}
$$

MachineIR retains decoded instructions, locations, control flow, and effect footprints. StateIR assigns versions to state components. FunctionIR carries function and ABI facts into the next representation. CIR supplies statements and terminators for C emission. LLVM is an optional export, as recorded in [ADR 0019](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/docs/adr/0019-llvm-is-an-export-format.md).

The native component universe includes registers, flags, control state, and memory regions. In the inspected implementation, `machine_state_components` includes stack, image, TLS, heap, volatile, and unknown memory. These regions are a conservative way of recording dependencies, not a claim that every pointer has been resolved.

For each component $c$, `populate_component_ssa` allocates a version at a block input and new versions for instruction outputs. A block's component phi records each predecessor's outgoing version:

$$ {#component-ssa}
c_v^{\mathrm{in}}
=\phi\!\left(
[c_{p_1}^{\mathrm{out}},p_1],\ldots,
[c_{p_k}^{\mathrm{out}},p_k]
\right).
$$

Entry components start at version zero. That is a name for incoming architectural state, not an assertion that the contents are numerically zero or determined by two scalar arguments. This is a broader model than the compatibility backend's definite-initialization gate.

Memory needs versions because its writes affect later reads. Consider a store followed by a load:

$$ {#memory-dependence}
\begin{aligned}
M_1&=\operatorname{store}(M_0,a,x),\\
y&=\operatorname{load}(M_1,b).
\end{aligned}
$$

Replacing $M_1$ by $M_0$ in the load needs a reason: for single-byte accesses, proving $a\ne b$ would suffice in this simple memory model. For multi-byte accesses, the byte ranges must be disjoint. A register-level SSA graph alone supplies neither proof.

The equations illustrate the dependency; HydIR's StateIR records component versions and effect descriptions rather than literally storing these mathematical arrays. Its `instruction_components` function makes a memory write consume the previous region version and produce a new one. Uncertain pointer effects include heap and unknown-memory dependencies. That prevents treating two unexplained accesses as independent merely because their address expressions look different.

Undefined flags and opaque effects also produce versions. An undefined flag must not reuse its old value, and an unknown instruction must not vanish as though it were a no-op. Both `Exact` and `Unknown` state operations carry input and output component lists. This lets later views retain the dependency even when its exact arithmetic is unavailable.

There are therefore two distinct questions at a join: **which predecessor supplied the state**, and **how precisely do we know the operation that produced it**? Phi nodes answer the first. Semantic fidelity and effect metadata answer the second. Well-formed SSA does not turn an unknown operation into a known one.

Native LLVM export preserves this distinction through exact or opaque effect descriptors and hooks. A verifier accepting the export establishes its LLVM structure, not standalone executable equivalence. It also cannot make a partial native result safe to rewrite. The native unit keeps structural completeness, semantic fidelity, verification status, and rewrite readiness as separate fields.

## Leaving SSA requires simultaneous assignments

C has ordinary mutable variables, so an SSA phi must be lowered. On an edge into a block with several phis, the selected incoming values conceptually move into all destinations at once:

$$ {#parallel-assignment}
(x_1,\ldots,x_k)
\leftarrow_{\parallel}
(e_1,\ldots,e_k).
$$

Every right-hand expression is evaluated in the state *before* any phi destination is updated. Ignoring that timing breaks cycles.

For example, an edge may swap two values:

$$ {#swap}
(x,y)\leftarrow_{\parallel}(y,x).
$$

Starting with $(x,y)=(7,11)$, the intended result is $(11,7)$. The naive sequence `x = y; y = x;` instead produces $(11,11)$, because the second assignment reads the new $x$.

The scalar LLVM-to-C backend's [`edge` function](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-c/src/lib.rs) first captures every source in an edge-local temporary, then writes every destination:

~~~c
uint64_t edge_0 = v_y;
uint64_t edge_1 = v_x;
v_x = edge_0;
v_y = edge_1;
goto L_target;
~~~

The general construction is:

$$ {#parallel-copy-lowering}
\begin{aligned}
t_i&:=\operatorname{eval}(e_i,\sigma)
&& (1\le i\le k),\\
\sigma'&:=\sigma[x_1\mapsto t_1,\ldots,x_k\mapsto t_k].
\end{aligned}
$$

Since temporaries are fresh, evaluating one source cannot change another source's value. That directly establishes agreement with the simultaneous update. More elaborate out-of-SSA algorithms can reduce copies and temporary storage; the simple construction makes the semantic argument short.

<section class="lab" id="copy-lab" hidden aria-labelledby="copy-lab-title">
<h3 id="copy-lab-title">A phi edge that swaps two values</h3>
<p>The incoming state is x = 7, y = 11. Compare the two ways of executing the same edge.</p>
<div class="lab-controls"><button type="button" data-copy-mode="before" aria-pressed="true">Before the edge</button><button type="button" data-copy-mode="sequential" aria-pressed="false">Sequential copies</button><button type="button" data-copy-mode="parallel" aria-pressed="false">Parallel copies</button></div>
<div role="status" aria-live="polite" aria-atomic="true"><p class="copy-result" id="copy-values">x = 7, y = 11</p><p id="copy-explanation">Both original values are still available.</p><pre id="copy-code">Incoming edge: (x, y) ← (y, x)</pre></div>
</section>

The copies are emitted inside the chosen branch arm before its `goto`. Thus each arm has its own edge semantics. There is no requirement to guess an original source-level `if` or `while` merely to emit correct direct control flow.

The C parser also checks that every phi's predecessor set matches the graph's predecessor set. An operand from a nonexistent block, or a missing operand for a real edge, cannot be treated as an optional annotation.

## Optimization follows the semantic model

A raw lift is a starting representation. It may contain copies expressed as addition by zero, flag calculations whose results are never consumed, and blocks that exist only to preserve instruction boundaries.

The scalar LLVM experiment's [transform module](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-transform/src/lib.rs) allows up to four distinct named passes: `instcombine`, `sccp`, `simplifycfg`, and `dce`. That experiment requires LLVM `opt` version 14.0.6, retains raw/before/after artifacts, and runs verifier checks around the transformations. These are not prerequisites for native C emission.

These passes answer different questions. Algebraic simplification may replace $x+0$ with $x$. Dead-code elimination can remove a flag computation that has no remaining uses. Control-flow simplification may eliminate an unnecessary jump. Sparse conditional constant propagation reasons about both values and executable edges. The [LLVM pass reference](https://releases.llvm.org/14.0.0/docs/Passes.html) describes their intended roles.

A useful simplified SCCP value domain is:

$$ {#constant-domain}
\bot\ \sqsubseteq\ \operatorname{Const}(c)\ \sqsubseteq\ \top.
$$

Different constants are incomparable. Here $\bot$ means no value information has yet been established in the propagation process; it is not permission to read an uninitialized machine register. $\top$ means the value is not represented by one known constant. Joining two constant facts gives:

$$ {#constant-join}
\operatorname{Const}(c)\sqcup\operatorname{Const}(d)=
\begin{cases}
\operatorname{Const}(c),&c=d,\\
\top,&c\ne d.
\end{cases}
$$

If a branch condition becomes known, the analysis can restrict propagation to the executable successor. A phi then joins values only from edges established as executable by that analysis. This is more precise than merging every syntactic predecessor indiscriminately.

It does not follow that SCCP will reduce maximum of two arbitrary arguments to a constant. The inputs are unconstrained. Optimizations may expose a more compact conditional expression, but the result must remain input-dependent.

The front end's semantic promises are crucial. If a wrapping machine ADD were emitted with an unjustified no-overflow promise, an optimizer could exploit that promise and still be correct with respect to the *wrong* IR. Correct optimization cannot repair an incorrect initial model.

Similarly, passing `opt -passes=verify` establishes IR well-formedness, not binary equivalence. The verifier is not independently executing or proving the source machine instructions.

## Source-shaped C is another transformation

Labels and gotos are a direct representation of a graph. Recovering familiar syntax adds a separate interpretation step: deciding whether a region corresponds to an `if`, a loop, or a recognized expression.

For the maximum fixture, the graph and branch equations justify:

~~~c
return arg0 >= arg1 ? arg0 : arg1;
~~~

That justification depends on the whole relevant shape: which comparison defines CF, which jump reads it, which path writes which value, whether another operation changes the result, and where the paths rejoin.

The scalar `emit_structured_c` implementation validates the grammar, then uses `matches_unsigned_max` to follow the relevant control and value dependencies. It walks from the prologue to the branch, resolves copies to find the unsigned comparison of the two arguments, checks its inversion, and follows each arm to its returned value. The true arm must return the first argument and the false arm the second. Simply containing a comparison and two moves is insufficient.

Native structured C uses graph algorithms over CIR. Its supported shapes include acyclic conditionals, guarded switches, and several loop forms. Postdominators help identify where branch arms reconverge; a backedge $t\to h$ with $h$ dominating $t$ identifies a candidate natural-loop header:

$$ {#loop-backedge}
(t,h)\in E\quad\land\quad h\operatorname{dom}t.
$$

Under the chosen exit convention, $q$ postdominates $v$ when every path from $v$ to the exit includes $q$. Multiple returns need an explicit common exit convention, and nonterminating regions need separate treatment. Postdominance is not itself a proof that a branch or loop terminates.

The native emitter checks the supported region shape before selecting a structured form and retains direct control flow for other cases. Syntactic validity, pattern recognition, and semantic equivalence remain separate claims. A recognizable loop header alone does not justify dropping an exit, an opaque effect, or a state update.

The direct CFG output remains the useful representation for explaining SSA elimination. Its mechanics do not depend on recovering the author's original control structures.

## A may analysis joins in the other direction

The scalar lifter's initialization pass asks what is true on every incoming path. HydIR's separate global-effect analysis asks which accesses might occur, including accesses made by direct callees. The word “might” changes the join operation.

Let $\mathcal G$ be the finite set of tracked global references. Represent a summary as a triple of possible reads, possible writes, and an unknown-effects flag:

$$ {#effect-domain}
S_f=(R_f,W_f,U_f)
\in
\mathcal P(\mathcal G)\times
\mathcal P(\mathcal G)\times
\{0,1\}.
$$

The join preserves every enumerated possibility:

$$ {#effect-join}
(R_1,W_1,U_1)\sqcup(R_2,W_2,U_2)
=
(R_1\cup R_2,\ W_1\cup W_2,\ U_1\lor U_2).
$$

If $D_f$ is a function's direct summary and $C(f)$ its resolved direct callees, the propagation equation is:

$$ {#effect-fixed-point}
S_f
=D_f\sqcup
\bigsqcup_{g\in C(f)}S_g.
$$

A caller of a function that may write a global must itself carry that possible write. A caller of an unresolved or unknown-effect function must retain the uncertainty.

The unknown flag is essential. In the concrete meaning of the report, $U_f=1$ says that the enumerated addresses are not exhaustive. An empty write set accompanied by $U_f=1$ is not a purity result. In that state, the absence of an address from $W_f$ supplies no negative guarantee about it.

The source distinguishes known RIP-relative global references from unresolved memory behavior. It also treats call/return stack bookkeeping as stack-local under its documented stack contract. Those modeling assumptions belong to the result, not just to an implementation comment.

This pass can report call and memory information even where exact lowering is unavailable. Effect analysis, scalar lifting, and native recovery have different contracts; success in one does not silently establish the guarantees of another.

## Recursion is a finite set problem here

Recursion makes effect summaries mutually dependent. If $f$ calls $g$ and $g$ calls $f$, computing each summary once in source order cannot propagate all information.

For an example, let $f$ directly read global $\alpha$ and $g$ directly write global $\beta$:

$$ {#recursive-effects}
\begin{aligned}
D_f&=(\{\alpha\},\varnothing,0),\\
D_g&=(\varnothing,\{\beta\},0),\\
C(f)&=\{g\},\qquad C(g)=\{f\}.
\end{aligned}
$$

Starting with the direct summaries and applying the join equations repeatedly gives:

$$ {#recursive-solution}
S_f=S_g=(\{\alpha\},\{\beta\},0).
$$

Information only grows. Each tracked reference can enter a read or write set once, and each unknown flag can change from zero to one once. Across $N$ selected functions and $G$ tracked references, there are at most $N(2G+1)$ such additions. Again, this counts strict information changes, not total scanning cost.

The least fixed point is enough because the analysis begins with direct facts and adds only the consequences of the resolved call graph. No widening is needed for this finite domain. This is a small, concrete instance of the lattice-based reasoning developed in [Cousot and Cousot's abstract interpretation framework](https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml).

A strongly connected component groups functions that can reach one another through calls. Collapsing those components gives an acyclic graph and can guide an efficient schedule. HydIR computes SCC identifiers for its summaries, but the inspected implementation performs repeated global scans; it should not be described as an SCC-scheduled solver.

The contrast with initialization is now precise. Initialization starts at the top and removes unsupported guarantees using intersection. Effect propagation starts with direct possibilities and adds consequences using union. Both terminate because the domains are finite, but the meanings of their sets are different.

| Analysis | Meaning of membership | Merge | Direction |
| --- | --- | --- | --- |
| Definite initialization | A field is defined on every modeled incoming path | Intersection | Remove unsupported guarantees |
| Global effects | An access is included among possible effects | Union | Add reachable possibilities |

Confusing these directions can create a false initialized read or a false claim of purity. The choice of lattice operation encodes the question being asked.

## Reproducing the stages

The native stages can be inspected separately for a selected function:

~~~sh
cargo run --locked --bin hydirctl -- lift fixture.elf \
  --function hydir_max2 --ir state
cargo run --locked --bin hydirctl -- lift fixture.elf \
  --function hydir_max2 --ir cir
cargo run --locked --bin hydirctl -- decompile fixture.elf \
  --function hydir_max2 --view low
cargo run --locked --bin hydirctl -- decompile fixture.elf \
  --function hydir_max2 --view unit
~~~

For the scalar LLVM compatibility example, use the explicit prototype assertion and a compatible toolchain:

~~~sh
cargo run --locked --bin hydirctl -- cfg fixture.elf hydir_max2
cargo run --locked --bin hydirctl -- lift fixture.elf hydir_max2 \
  --assume-u64x2 --output max2.ll
opt -passes=verify -disable-output max2.ll
cargo run --locked --bin hydirctl -- decompile fixture.elf hydir_max2 \
  --assume-u64x2 --output max2.c
~~~

The fixture path in those commands is a placeholder. The repository's [`demo-local.sh`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/scripts/demo-local.sh) creates its trusted fixtures and exercises the complete local comparison path. [`demo-corpus.sh`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/scripts/demo-corpus.sh) adds the scalar corpus. Native differential execution requires Linux x86-64; the project also supplies a Docker demo runner.

Each artifact answers a narrower question than “did we decompile the program?” The CFG records selected instruction boundaries and edges. Initialization checks justify modeled reads. SSA records values per incoming edge. The C emitter translates that graph into a restricted C grammar. The verifier checks LLVM structure. Differential tests compare chosen observations for chosen inputs.

The theory is useful because it identifies the seams between those artifacts. At every seam, one can state the object being preserved, the assumptions under which it is preserved, and the evidence that currently checks it.

## Reading the implementation

Implementation descriptions were checked against revision `b00835d`, and source links are pinned to it. Native and scalar compatibility paths are identified separately.

- [`hydir-backend/src/cfg.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-backend/src/cfg.rs): `recover_bounded`, `Node::defs`, `Node::reads`, `Node::kills`, `analyze`, and `lift_cfg` implement scalar graph recovery, initialization, and explicit SSA.
- [`hydir-decompile/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-decompile/src/lib.rs): `lower_state_ir`, `populate_component_ssa`, and `instruction_components` implement native state flow and component versions.
- [`hydir-c/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-c/src/lib.rs): `parse_phi`, `edge`, and `emit_c` implement the restricted C backend; `emit_structured_c` is a separate presentation path.
- [`hydir-transform/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-transform/src/lib.rs): the pass allowlist, LLVM version check, retained artifacts, and verifier invocations.
- [`hydir-analysis/src/lib.rs`](https://github.com/Achxy/hydir-2/blob/b00835d7568801738a2ee01e42f6bd11ae537e81/crates/hydir-analysis/src/lib.rs): direct effect collection, union-based summary propagation, uncertainty, and SCC labels.

For the arithmetic inside each state transformer, return to [From Bitvectors to Behavior](/articles/bitvectors-to-behavior). The graph algorithms preserve values only as faithfully as those local semantics define them.
