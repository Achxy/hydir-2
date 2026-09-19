# HydIR interchange schemas

The files under `hydir_interchange/` and `hydir_patch/` are the minimum public
Protocol Buffer schemas used by HydIR's native interchange services. Their
field numbers preserve compatibility with the pinned external references.

- External source commit: `d97aee937ebb6d1cb8a362748c56414404eb75ff`
- Schema source commit: `52f9638b023417c9bdbbb1791867cacc38c68888`
- Upstream license: GNU Affero General Public License v3.0 only

HydIR does not vendor the upstream lifting, decompilation, or patching
algorithms. The schemas are compiled into the native Rust API contract only.
