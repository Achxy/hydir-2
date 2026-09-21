.text
.globl hydir_scalar_float_arithmetic
.type hydir_scalar_float_arithmetic,@function
hydir_scalar_float_arithmetic:
  addss %xmm1, %xmm0
  subsd %xmm3, %xmm2
  mulss (%rdi), %xmm0
  divsd (%rsi), %xmm1
  vaddss %xmm2, %xmm1, %xmm0
  vsubsd %xmm5, %xmm4, %xmm3
  vmulss (%rdi), %xmm6, %xmm7
  vdivsd (%rsi), %xmm8, %xmm9
  sqrtss %xmm1, %xmm0
  sqrtsd (%rdi), %xmm2
  vsqrtss %xmm5, %xmm4, %xmm3
  vsqrtsd (%rsi), %xmm6, %xmm7
  cvtss2sd %xmm1, %xmm0
  cvtsd2ss (%rdi), %xmm2
  vcvtss2sd %xmm5, %xmm4, %xmm3
  vcvtsd2ss (%rsi), %xmm6, %xmm7
  cvtsi2ss %eax, %xmm0
  cvtsi2sd %rax, %xmm1
  vcvtsi2ss %ecx, %xmm2, %xmm3
  vcvtsi2sd %rcx, %xmm4, %xmm5
  cvtss2si %xmm0, %eax
  cvttsd2si %xmm1, %rax
  vcvtss2si %xmm3, %ecx
  vcvttsd2si %xmm5, %rcx
  ret
.size hydir_scalar_float_arithmetic, .-hydir_scalar_float_arithmetic

.globl hydir_scalar_float_compare
.type hydir_scalar_float_compare,@function
hydir_scalar_float_compare:
  ucomiss %xmm1, %xmm0
  seta %al
  comisd %xmm3, %xmm2
  setp %cl
  vucomiss %xmm5, %xmm4
  setbe %dl
  vcomisd %xmm7, %xmm6
  setne %sil
  ret
.size hydir_scalar_float_compare, .-hydir_scalar_float_compare
