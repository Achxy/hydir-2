.intel_syntax noprefix
.text

.globl hydir_avx512_opaque
.type hydir_avx512_opaque,@function
hydir_avx512_opaque:
  vpxord zmm0, zmm0, zmm0
  vaddps zmm1, zmm0, zmm2
  vmovdqu64 zmm4, zmm5
  vmovdqu64 zmmword ptr [rdi], zmm4
  vmovdqu64 zmm6, zmmword ptr [rsi]
  vmovdqa64 zmm7, zmmword ptr [rdx]
  vpxord zmm3 {k1}, zmm1, zmm2
  vpxord zmm3 {k1}{z}, zmm1, zmm2
  vpandq zmm4 {k2}, zmm5, zmm6
  vpandq zmm4 {k2}{z}, zmm5, zmm6
  vporq zmm7 {k3}, zmm8, zmm9
  vporq zmm7 {k3}{z}, zmm8, zmm9
  vmovdqu32 zmm0 {k1}, zmm1
  vmovdqu32 zmm0 {k1}{z}, zmm1
  vmovdqu64 zmm2 {k2}, zmmword ptr [rdi]
  vmovdqu64 zmm2 {k2}{z}, zmmword ptr [rdi]
  vmovdqu64 zmmword ptr [rsi] {k3}, zmm4
  vmovdqa32 zmm5 {k4}, zmmword ptr [rdx]
  vaddps zmm0 {k1}, zmm1, zmm2
  vaddps zmm0 {k1}{z}, zmm1, zmm2
  vaddps zmm3 {k2}, zmm4, dword ptr [rdi]{1to16}
  vaddpd zmm5 {k3}{z}, zmm6, qword ptr [rsi]{1to8}
  vsubpd zmm7, zmm8, qword ptr [rsi]{1to8}
  vpopcntb zmm0 {k1}, zmm1
  vpopcntb zmm0 {k1}{z}, zmm1
  vpopcntb zmm2 {k2}, zmmword ptr [rdi]
  vpopcntb zmm2 {k2}{z}, zmmword ptr [rdi]
  vgf2p8affineqb zmm0 {k1}, zmm1, zmm2, 0x63
  vgf2p8affineqb zmm0 {k1}{z}, zmm1, zmm2, 0x63
  vgf2p8affineqb zmm3 {k2}, zmm4, qword ptr [rdi]{1to8}, 0
  vgf2p8affineqb zmm3 {k2}{z}, zmm4, qword ptr [rdi]{1to8}, 0
  vpcmpuq k1 {k2}, zmm3, zmm4, 4
  vpcmpuq k1 {k2}, zmm3, qword ptr [rdi]{1to8}, 1
  vpcmpuq k1, zmm3, qword ptr [rdi]{1to8}, 1
  vpcompressq zmmword ptr [rdi] {k1}, zmm2
  vpcompressq zmm3 {k2}, zmm4
  vpcompressq zmm3 {k2}{z}, zmm4
  vpxord zmm5 {k1}, zmm6, zmmword ptr [rdi]
  vpermb zmm10 {k2}, zmm11, zmmword ptr [rsi]
  vpermi2b zmm12 {k3}, zmm13, zmmword ptr [rdx]
  ret
.size hydir_avx512_opaque, .-hydir_avx512_opaque

.section .note.GNU-stack,"",@progbits
