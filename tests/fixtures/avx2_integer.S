.intel_syntax noprefix

.text
.globl avx2_integer_kernel
.type avx2_integer_kernel, @function
avx2_integer_kernel:
    vpbroadcastq ymm1, qword ptr [rip + .Lqword]
    vpmuludq ymm10, ymm9, ymm1
    vpsrlq ymm11, ymm9, 32
    vpaddq ymm10, ymm10, ymm11
    vpsllq ymm10, ymm10, 32
    vextracti128 xmm1, ymm0, 1
    vpshufd xmm1, xmm0, 0xee
    vbroadcastss ymm0, dword ptr [rip + .Ldword]
    vpaddb ymm2, ymm3, ymm4
    vpaddw ymm5, ymm6, ymm7
    vpaddd ymm8, ymm9, ymm10
    vpsubb ymm11, ymm12, ymm13
    vpsubw ymm14, ymm15, ymm0
    vpsubd ymm1, ymm2, ymm3
    vpsubq ymm4, ymm5, ymm6
    vpmullw ymm7, ymm8, ymm9
    vpmulld ymm10, ymm11, ymm12
    vpcmpeqb ymm13, ymm14, ymm15
    vpcmpeqw ymm0, ymm1, ymm2
    vpcmpeqd ymm3, ymm4, ymm5
    vpcmpeqq ymm6, ymm7, ymm8
    vpcmpgtb ymm9, ymm10, ymm11
    vpcmpgtw ymm12, ymm13, ymm14
    vpcmpgtd ymm15, ymm0, ymm1
    vpcmpgtq ymm2, ymm3, ymm4
    vpminub ymm5, ymm6, ymm7
    vpminuw ymm8, ymm9, ymm10
    vpminud ymm11, ymm12, ymm13
    vpminsw ymm14, ymm15, ymm0
    vpminsd ymm1, ymm2, ymm3
    vpmaxub ymm4, ymm5, ymm6
    vpmaxuw ymm7, ymm8, ymm9
    vpmaxud ymm10, ymm11, ymm12
    vpmaxsw ymm13, ymm14, ymm15
    vpmaxsd ymm0, ymm1, ymm2
    vpunpcklbw ymm3, ymm4, ymm5
    vpunpcklwd ymm6, ymm7, ymm8
    vpunpckldq ymm9, ymm10, ymm11
    vpunpcklqdq ymm12, ymm13, ymm14
    vpunpckhbw ymm15, ymm0, ymm1
    vpunpckhwd ymm2, ymm3, ymm4
    vpunpckhdq ymm5, ymm6, ymm7
    vpunpckhqdq ymm8, ymm9, ymm10
    vpsllw ymm11, ymm12, 7
    vpslld ymm13, ymm14, 13
    vpsrlw ymm15, ymm0, 9
    vpsrld ymm1, ymm2, 17
    vpsraw ymm3, ymm4, 15
    vpsrad ymm5, ymm6, 31
    vpshufb ymm11, ymm12, ymm13
    vinserti128 ymm14, ymm15, xmm0, 1
    vpaddsb ymm0, ymm1, ymm2
    vpaddsw ymm3, ymm4, ymm5
    vpaddusb ymm6, ymm7, ymm8
    vpaddusw ymm9, ymm10, ymm11
    vpsubsb ymm12, ymm13, ymm14
    vpsubsw ymm15, ymm0, ymm1
    vpsubusb ymm2, ymm3, ymm4
    vpsubusw ymm5, ymm6, ymm7
    vpacksswb ymm8, ymm9, ymm10
    vpackssdw ymm11, ymm12, ymm13
    vpackuswb ymm14, ymm15, ymm0
    vpackusdw ymm1, ymm2, ymm3
    andn rax, rsi, rax
    vzeroupper
    ret
.size avx2_integer_kernel, .-avx2_integer_kernel

.section .rodata,"a",@progbits
.p2align 3
.Lqword:
    .quad 0x9e3779b97f4a7c15
.Ldword:
    .long 0x5a5a5a5a

.section .note.GNU-stack,"",@progbits
