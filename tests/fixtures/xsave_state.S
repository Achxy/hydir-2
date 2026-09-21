.intel_syntax noprefix
.text

.globl hydir_xsave_state
.type hydir_xsave_state,@function
hydir_xsave_state:
  xsave64 [rdi]
  xsaveopt64 [rsi]
  xsavec64 [r10]
  xsaves64 [r11]
  xrstor64 [r8]
  xrstors64 [r9]
  ret
.size hydir_xsave_state, .-hydir_xsave_state

.section .note.GNU-stack,"",@progbits
