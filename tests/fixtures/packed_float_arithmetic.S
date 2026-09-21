.text
.globl hydir_packed_float_arithmetic
.type hydir_packed_float_arithmetic,@function
hydir_packed_float_arithmetic:
  addps %xmm1, %xmm0
  subpd %xmm3, %xmm2
  mulps (%rdi), %xmm0
  divpd (%rsi), %xmm1
  vaddps %ymm2, %ymm1, %ymm0
  vsubpd %ymm5, %ymm4, %ymm3
  vmulps (%rdi), %xmm6, %xmm7
  vdivpd (%rsi), %xmm8, %xmm9
  sqrtps %xmm1, %xmm0
  sqrtpd (%rdi), %xmm2
  vsqrtps %ymm4, %ymm3
  vsqrtpd (%rsi), %xmm5
  cvtdq2ps %xmm1, %xmm0
  cvtps2dq (%rdi), %xmm2
  cvttps2dq %xmm4, %xmm3
  vcvtdq2ps %ymm6, %ymm5
  vcvtps2dq (%rsi), %ymm7
  vcvttps2dq %ymm9, %ymm8
  cvtps2pd %xmm1, %xmm0
  cvtpd2ps %xmm3, %xmm2
  cvtdq2pd %xmm5, %xmm4
  cvtpd2dq %xmm7, %xmm6
  vcvtps2pd %xmm9, %ymm8
  vcvtpd2ps %ymm11, %xmm10
  vcvtdq2pd %xmm13, %ymm12
  vcvttpd2dq %ymm15, %xmm14
  ret
.size hydir_packed_float_arithmetic, .-hydir_packed_float_arithmetic

.globl hydir_packed_i32_to_float
.type hydir_packed_i32_to_float,@function
hydir_packed_i32_to_float:
  cvtdq2ps %xmm0, %xmm0
  ret
.size hydir_packed_i32_to_float, .-hydir_packed_i32_to_float

.globl hydir_packed_float_to_i32
.type hydir_packed_float_to_i32,@function
hydir_packed_float_to_i32:
  vcvtps2dq %ymm0, %ymm0
  ret
.size hydir_packed_float_to_i32, .-hydir_packed_float_to_i32
