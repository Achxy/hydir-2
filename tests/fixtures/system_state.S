.text

.globl hydir_system_state
.type hydir_system_state,@function
hydir_system_state:
    cpuid
    rdtsc
    rdtscp
    xgetbv
    rdrand %rax
    rdseed %rbx
    retq
.size hydir_system_state, .-hydir_system_state

.section .note.GNU-stack,"",@progbits
