.text
.globl hydir_cfg_min
.type hydir_cfg_min,@function
hydir_cfg_min:
    cmpq %rsi, %rdi
    jb .Lmin_left
    movq %rsi, %rax
    jmp .Lmin_done
.Lmin_left:
    movq %rdi, %rax
.Lmin_done:
    retq
.size hydir_cfg_min, .-hydir_cfg_min

.globl hydir_cfg_sum
.type hydir_cfg_sum,@function
hydir_cfg_sum:
    movq $0, %rax
.Lsum_loop:
    cmpq %rsi, %rdi
    jae .Lsum_done
    addq %rdi, %rax
    addq $1, %rdi
    jmp .Lsum_loop
.Lsum_done:
    retq
.size hydir_cfg_sum, .-hydir_cfg_sum

.globl hydir_cfg_add_flags
.type hydir_cfg_add_flags,@function
hydir_cfg_add_flags:
    movq %rdi, %rax
    addq %rsi, %rax
    jz .Ladd_zero
    retq
.Ladd_zero:
    movq $1, %rax
    retq
.size hydir_cfg_add_flags, .-hydir_cfg_add_flags

.globl hydir_cfg_add_snapshot
.type hydir_cfg_add_snapshot,@function
hydir_cfg_add_snapshot:
    movq %rdi, %rax
    addq %rsi, %rax
    movq $99, %rax
    jnz .Ladd_snapshot_nonzero
    movq $1, %rax
    retq
.Ladd_snapshot_nonzero:
    movq $2, %rax
    retq
.size hydir_cfg_add_snapshot, .-hydir_cfg_add_snapshot

.globl hydir_cfg_sub_flags
.type hydir_cfg_sub_flags,@function
hydir_cfg_sub_flags:
    movq %rdi, %rax
    subq %rsi, %rax
    jz .Lsub_zero
    retq
.Lsub_zero:
    movq $11, %rax
    retq
.size hydir_cfg_sub_flags, .-hydir_cfg_sub_flags

.globl hydir_cfg_and_flags
.type hydir_cfg_and_flags,@function
hydir_cfg_and_flags:
    movq %rdi, %rax
    andq %rsi, %rax
    jnz .Land_nonzero
    movq $13, %rax
    retq
.Land_nonzero:
    retq
.size hydir_cfg_and_flags, .-hydir_cfg_and_flags

.globl hydir_cfg_xor_flags
.type hydir_cfg_xor_flags,@function
hydir_cfg_xor_flags:
    xorq %rax, %rax
    jz .Lxor_zero
    movq $0, %rax
    retq
.Lxor_zero:
    movq $17, %rax
    retq
.size hydir_cfg_xor_flags, .-hydir_cfg_xor_flags

.globl hydir_cfg_memory
.type hydir_cfg_memory,@function
hydir_cfg_memory:
    movq (%rdi), %rax
    retq
.size hydir_cfg_memory, .-hydir_cfg_memory

.globl hydir_cfg_memory_byte
.type hydir_cfg_memory_byte,@function
hydir_cfg_memory_byte:
    movzbq (%rdi), %rax
    retq
.size hydir_cfg_memory_byte, .-hydir_cfg_memory_byte

.globl hydir_cfg_array_sum
.type hydir_cfg_array_sum,@function
hydir_cfg_array_sum:
    xorq %rax, %rax
    testq %rsi, %rsi
    jz .Larray_sum_done
.Larray_sum_loop:
    movq (%rdi), %rdx
    addq %rdx, %rax
    addq $8, %rdi
    subq $1, %rsi
    jnz .Larray_sum_loop
.Larray_sum_done:
    retq
.size hydir_cfg_array_sum, .-hydir_cfg_array_sum

.globl hydir_cfg_array_fill
.type hydir_cfg_array_fill,@function
hydir_cfg_array_fill:
    xorq %rax, %rax
    testq %rdx, %rdx
    jz .Larray_fill_done
.Larray_fill_loop:
    movq %rsi, (%rdi)
    addq $8, %rdi
    subq $1, %rdx
    jnz .Larray_fill_loop
.Larray_fill_done:
    retq
.size hydir_cfg_array_fill, .-hydir_cfg_array_fill

.globl hydir_cfg_indexed_sum
.type hydir_cfg_indexed_sum,@function
hydir_cfg_indexed_sum:
    xorq %rax, %rax
    xorq %rdx, %rdx
.Lindexed_sum_loop:
    cmpq %rsi, %rdx
    jae .Lindexed_sum_done
    movq (%rdi,%rdx,8), %rcx
    addq %rcx, %rax
    addq $1, %rdx
    jmp .Lindexed_sum_loop
.Lindexed_sum_done:
    retq
.size hydir_cfg_indexed_sum, .-hydir_cfg_indexed_sum

.globl hydir_cfg_overlap
.type hydir_cfg_overlap,@function
hydir_cfg_overlap:
    movq %rsi, (%rdi)
    movq 1(%rdi), %rax
    retq
.size hydir_cfg_overlap, .-hydir_cfg_overlap

.globl hydir_cfg_negative_offset
.type hydir_cfg_negative_offset,@function
hydir_cfg_negative_offset:
    movq -8(%rdi), %rax
    retq
.size hydir_cfg_negative_offset, .-hydir_cfg_negative_offset

.globl hydir_cfg_ctx_step
.type hydir_cfg_ctx_step,@function
hydir_cfg_ctx_step:
    movq 8(%rdi), %rax
    testq %rax, %rax
    jz .Lctx_step_zero
    movq 0(%rdi), %rdx
    addq %rdx, %rax
    movq %rax, 8(%rdi)
    retq
.Lctx_step_zero:
    movq 0(%rdi), %rax
    retq
.size hydir_cfg_ctx_step, .-hydir_cfg_ctx_step

.globl hydir_cfg_ctx_drain
.type hydir_cfg_ctx_drain,@function
hydir_cfg_ctx_drain:
    xorq %rax, %rax
.Lctx_drain_loop:
    movq 8(%rdi), %rdx
    testq %rdx, %rdx
    jz .Lctx_drain_done
    addq %rdx, %rax
    subq $1, %rdx
    movq %rdx, 8(%rdi)
    jmp .Lctx_drain_loop
.Lctx_drain_done:
    retq
.size hydir_cfg_ctx_drain, .-hydir_cfg_ctx_drain

.globl hydir_cfg_ctx_shift
.type hydir_cfg_ctx_shift,@function
hydir_cfg_ctx_shift:
    addq $8, %rdi
    movq 0(%rdi), %rax
    retq
.size hydir_cfg_ctx_shift, .-hydir_cfg_ctx_shift

.globl hydir_cfg_callee_saved
.type hydir_cfg_callee_saved,@function
hydir_cfg_callee_saved:
    movq %rdi, %rbx
    movq %rbx, %rax
    retq
.size hydir_cfg_callee_saved, .-hydir_cfg_callee_saved

.globl hydir_cfg_nested
.type hydir_cfg_nested,@function
hydir_cfg_nested:
    cmpq %rsi, %rdi
    jb .Lnested_less
    testq %rdi, %rdi
    je .Lnested_zero
    movq %rdi, %rax
    retq
.Lnested_zero:
    movq %rsi, %rax
    retq
.Lnested_less:
    movq $7, %rax
    retq
.size hydir_cfg_nested, .-hydir_cfg_nested

.globl hydir_cfg_signed_count
.type hydir_cfg_signed_count,@function
hydir_cfg_signed_count:
    movq $0, %rax
.Lsigned_loop:
    cmpq %rsi, %rdi
    jge .Lsigned_done
    addq $1, %rax
    addq $1, %rdi
    jmp .Lsigned_loop
.Lsigned_done:
    retq
.size hydir_cfg_signed_count, .-hydir_cfg_signed_count

.globl hydir_cfg_zeroing
.type hydir_cfg_zeroing,@function
hydir_cfg_zeroing:
    xorq %rax, %rax
    addq %rdi, %rax
    retq
.size hydir_cfg_zeroing, .-hydir_cfg_zeroing
