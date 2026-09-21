.text

.globl hydir_aligned_vectors
.type hydir_aligned_vectors,@function
hydir_aligned_vectors:
    movaps (%rdi), %xmm0
    movdqa %xmm0, (%rsi)
    vmovapd (%rdx), %ymm1
    vmovdqa %ymm1, (%rcx)
    retq
.size hydir_aligned_vectors, .-hydir_aligned_vectors

.section .note.GNU-stack,"",@progbits
