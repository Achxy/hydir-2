.intel_syntax noprefix
.text

.globl hydir_bmi2_shifts
.type hydir_bmi2_shifts,@function
hydir_bmi2_shifts:
  shlx rax, rsi, rdx
  shrx r8, r9, rcx
  sarx r10, r11, r12
  rorx r13, r14, 17
  pdep rax, rsi, rdx
  pext r8, r9, rcx
  ret
.size hydir_bmi2_shifts, .-hydir_bmi2_shifts

.section .note.GNU-stack,"",@progbits
