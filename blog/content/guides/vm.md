# Virtual-machine profiles and bounded exploration

HydIR can validate an analyst-scoped VM profile and explore host instructions with a virtual program counter (VPC) in the node identity. This is experimental host/VPC graph recovery, not automatic devirtualization.

## Describe the interpreter

VmProfile v1 binds the binary digest and records an entry, exits, VPC storage, bytecode ranges, context layout, and permitted guest effects. Each fact carries analyst, static-inference, or trace-observation evidence.

| Profile fact | Purpose |
| --- | --- |
| Entry and exits | Scope the interpreter region |
| VPC | Register or context-offset storage, with optional initial value |
| Bytecode ranges | Bound the bytes treated as VM instruction data |
| Context | Entry register, base register, and extent |
| Guest effects | Declared register/context effects, calls, returns, or disjoint memory |

An assertion that external memory writes are disjoint from VM state is an analyst assumption. It is not evidence that self-modifying bytecode is absent.

## Validate before exploring

```text
hydirctl vm-profile program.elf profile.json
hydirctl vm-explore program.elf profile.json
```

Construct the profile from the actual binary; addresses and the SHA-256 must match. The CLI bounds the profile JSON to 1 MiB. The [profile tests](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-vm/tests/profile.rs) show a complete fixture-backed profile construction using discovered ELF locations rather than hard-coded reusable addresses.

## Interpret the graph

A node key contains a host PC and an optional VPC. Two visits to the same host instruction with different known VPCs can therefore be different nodes. Nodes retain the decoded mnemonic and machine bytes. Edges distinguish next, taken, fallthrough, jump, call, call-return, exit, and unresolved flow.

The current explorer caps the graph at 10,000 nodes and the modeled context at 65,536 bytes. Unsupported instructions and addresses end edges explicitly. Inspect `unresolved_edges`, `hit_node_limit`, diagnostics, and observed guest effects with the graph.

`profile_validated` means the declared profile is internally consistent with the ELF. It does not mean a guest CFG was recovered or that rewriting is safe. The separate `guest_cfg_recovered` and `rewrite_ready` fields make those limits visible.

## Implementation references

- [Profile types and validation](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-vm/src/lib.rs)
- [VPC-sensitive exploration](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-vm/src/explore.rs)
