.text

.globl hydir_fx_state
.type hydir_fx_state,@function
hydir_fx_state:
    fxsave64 (%rdi)
    fxrstor64 (%rsi)
    stmxcsr 512(%rdi)
    ldmxcsr 512(%rsi)
    retq
.size hydir_fx_state, .-hydir_fx_state

.section .note.GNU-stack,"",@progbits
