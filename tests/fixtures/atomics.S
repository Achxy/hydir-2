.text

.globl hydir_atomic_fetch_add
.type hydir_atomic_fetch_add,@function
hydir_atomic_fetch_add:
    movq %rsi, %rax
    lock xaddq %rax, (%rdi)
    retq
.size hydir_atomic_fetch_add, .-hydir_atomic_fetch_add

.globl hydir_atomic_compare_exchange
.type hydir_atomic_compare_exchange,@function
hydir_atomic_compare_exchange:
    movq (%rsi), %rax
    lock cmpxchgq %rdx, (%rdi)
    lock cmpxchg8b 8(%rdi)
    lock cmpxchg16b 16(%rdi)
    sete %cl
    retq
.size hydir_atomic_compare_exchange, .-hydir_atomic_compare_exchange

.globl hydir_atomic_fence
.type hydir_atomic_fence,@function
hydir_atomic_fence:
    lock orl $0, -64(%rsp)
    lock incq (%rdi)
    lock decq 8(%rdi)
    lock negq 16(%rdi)
    lock notq 24(%rdi)
    lock adcq %rsi, 32(%rdi)
    lock sbbq $1, 40(%rdi)
    lock btsq %rsi, 48(%rdi)
    lock btrq $7, 56(%rdi)
    lock btcq %rsi, 64(%rdi)
    retq
.size hydir_atomic_fence, .-hydir_atomic_fence

.globl hydir_explicit_fences
.type hydir_explicit_fences,@function
hydir_explicit_fences:
    lfence
    sfence
    mfence
    retq
.size hydir_explicit_fences, .-hydir_explicit_fences

.section .note.GNU-stack,"",@progbits
