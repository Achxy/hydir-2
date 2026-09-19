# Irene3 interoperability schemas

The files under `anvill/`, `irene/`, and `irene3/` are the minimum public
Protocol Buffer schemas required for wire interoperability with the pinned
Irene3 reference.

- Irene3 source commit: `d97aee937ebb6d1cb8a362748c56414404eb75ff`
- Anvill schema commit: `52f9638b023417c9bdbbb1791867cacc38c68888`
- Upstream license: GNU Affero General Public License v3.0 only

HydIR does not vendor the upstream lifting, decompilation, or patching
algorithms. The schemas are compiled into the native Rust API contract only.
