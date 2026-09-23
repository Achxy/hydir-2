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

.globl hydir_cfg_memory
.type hydir_cfg_memory,@function
hydir_cfg_memory:
    movq (%rdi), %rax
    retq
.size hydir_cfg_memory, .-hydir_cfg_memory

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
