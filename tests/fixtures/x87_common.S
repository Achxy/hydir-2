.text

.globl hydir_x87_arithmetic
.type hydir_x87_arithmetic,@function
hydir_x87_arithmetic:
    fld1
    fldl (%rdi)
    fadd %st(1), %st
    fsqrt
    fxch %st(1)
    fmulp %st, %st(1)
    fstpl (%rsi)
    retq
.size hydir_x87_arithmetic, .-hydir_x87_arithmetic

.globl hydir_x87_integer
.type hydir_x87_integer,@function
hydir_x87_integer:
    fildq (%rdi)
    fiaddl 8(%rdi)
    fistpq (%rsi)
    retq
.size hydir_x87_integer, .-hydir_x87_integer

.globl hydir_x87_compare_transcendental
.type hydir_x87_compare_transcendental,@function
hydir_x87_compare_transcendental:
    flds (%rdi)
    flds 4(%rdi)
    fucomip %st(1), %st
    fstp %st(0)
    fldpi
    fsin
    fld1
    fyl2x
    fstpl (%rsi)
    retq
.size hydir_x87_compare_transcendental, .-hydir_x87_compare_transcendental

.globl hydir_x87_environment
.type hydir_x87_environment,@function
hydir_x87_environment:
    fnstcw (%rdi)
    fldcw (%rsi)
    fnstsw %ax
    fnstsw 2(%rdi)
    fnclex
    fninit
    retq
.size hydir_x87_environment, .-hydir_x87_environment

.globl hydir_x87_environment_images
.type hydir_x87_environment_images,@function
hydir_x87_environment_images:
    fldenv (%rdi)
    fnstenv (%rsi)
    fstenv 32(%rsi)
    frstor 64(%rdi)
    fnsave 128(%rsi)
    fsave 256(%rsi)
    retq
.size hydir_x87_environment_images, .-hydir_x87_environment_images

.section .note.GNU-stack,"",@progbits
