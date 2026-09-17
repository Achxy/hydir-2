# Measured development evaluation — 2026-09-18

These are observed fixture measurements, not throughput promises or general
binary-support estimates. The host was `Mac15,13`, Darwin arm64, with 16 GiB
RAM. The Rust binary was a Cargo development build; file data was warm in the
cache. The input was the same trusted, symbolized `hydir_max2` x86-64 ELF used
by `demo-remote.sh`. No Ghidra, server, Clang, or LLVM process participated in
these two frontend measurements.

| Operation | Command method | Observed wall time for 100 invocations | Quotient per invocation | Maximum resident size reported by `/usr/bin/time -l` |
| --- | --- | ---: | ---: | ---: |
| ELF inspect | 100 sequential `hydirctl inspect ... >/dev/null` processes in zsh | 0.47 s | 4.7 ms | 3,735,552 bytes |
| Scalar lift | 100 sequential `hydirctl lift ... --assume-u64x2 >/dev/null` processes in zsh | 0.33 s | 3.3 ms | 4,653,056 bytes |

The quotient includes process startup and shell loop overhead and is not an
isolated backend latency. The reported resident size is the command's maximum
observed value, not a per-function allocation count. The single-invocation
`/usr/bin/time -l` checks also exited 0, but their two-decimal wall clock
rounded to 0.04 s (inspect) and 0.00 s (lift), so the 100-invocation totals
above are the more useful readings. This is one run on one named host, not a
distribution or native Linux benchmark.

The behavior evaluation is in [EVIDENCE.md](EVIDENCE.md): 20 distinct scalar
functions plus a stripped variant matched 21,168/21,168 LLVM/native and
21,168/21,168 compiled-C/native controlled input pairs; three whole programs
matched five declared original/rebuilt runs. The authenticated remote, GUI
operation-probe, and Python SDK checks repeat subsets of those fixtures and
must not be added to the unique corpus count. Memory/latency profiling of the
Linux rebuild worker, hostile-input stress testing, optimized compiler output,
and an independent native Linux host remain release evaluation gaps.
