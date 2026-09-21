.intel_syntax noprefix
.text

.globl hydir_scalar_float_moves
.type hydir_scalar_float_moves,@function
hydir_scalar_float_moves:
  movss xmm0, xmm1
  movss xmm2, dword ptr [rdi]
  movss dword ptr [rsi], xmm2
  movsd xmm3, xmm4
  movsd xmm5, qword ptr [rdi]
  movsd qword ptr [rsi], xmm5
  vmovss xmm0, xmm1, xmm2
  vmovsd xmm3, xmm4, xmm5
  vmovss dword ptr [rsi], xmm0
  vmovsd qword ptr [rdi], xmm3
  ret
.size hydir_scalar_float_moves, .-hydir_scalar_float_moves

.section .note.GNU-stack,"",@progbits
