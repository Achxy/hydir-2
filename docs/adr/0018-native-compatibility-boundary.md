# ADR 0018: Native migration and compatibility boundary

Status: accepted, 2026-09-20.

The native decompiler is an additive path. Existing CLI forms, ProgramSpec and
DecompilationUnit files, projects, and gRPC v1/v2 methods remain supported while
ownership moves into `hydir-loader`, `hydir-ir`, and `hydir-decompile`.

`hydir-backend::import_elf` remains a compatibility facade over
`hydir-loader::import_elf`, including its established error type. Readers
migrate ProgramSpec v1-v4 and DecompilationUnit v1 in memory; they never rewrite
the source artifact. Writers emit only the current canonical version. A legacy
LLVM-derived unit maps into the v2 low-level view without gaining structural,
semantic, verification, or rewrite-readiness claims.

Native commands use explicit `--function`, `--ir`, and `--view` selectors so
legacy `--assume-u64x2` invocations retain their behavior. New analysis may
produce partial artifacts, but patch and rebuild paths continue to require
their independent existing proofs. Compatibility adapters may translate facts;
they may not manufacture evidence or upgrade uncertainty.
