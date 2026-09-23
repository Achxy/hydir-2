.text
.globl hydir_expression_conditions
.type hydir_expression_conditions,@function
hydir_expression_conditions:
    cmp %esi, %edi
    jae .Lunsigned_ge
    xor %eax, %eax
    ret
.Lunsigned_ge:
    test %esi, %esi
    je .Lzero
    cmp %esi, %edi
    jg .Lsigned_greater
    mov $1, %eax
    ret
.Lzero:
    mov $2, %eax
    ret
.Lsigned_greater:
    mov $3, %eax
    ret
.size hydir_expression_conditions, .-hydir_expression_conditions

.globl hydir_expression_arithmetic
.type hydir_expression_arithmetic,@function
hydir_expression_arithmetic:
    mov %edi, %eax
    add %esi, %eax
    sub %edx, %eax
    xor %ecx, %eax
    ret
.size hydir_expression_arithmetic, .-hydir_expression_arithmetic

.globl hydir_expression_arithmetic8
.type hydir_expression_arithmetic8,@function
hydir_expression_arithmetic8:
    add %sil, %al
    sub %dl, %al
    xor %cl, %al
    ret
.size hydir_expression_arithmetic8, .-hydir_expression_arithmetic8

.globl hydir_expression_arithmetic16
.type hydir_expression_arithmetic16,@function
hydir_expression_arithmetic16:
    add %si, %ax
    sub %dx, %ax
    xor %cx, %ax
    ret
.size hydir_expression_arithmetic16, .-hydir_expression_arithmetic16

.globl hydir_expression_arithmetic64
.type hydir_expression_arithmetic64,@function
hydir_expression_arithmetic64:
    add %rsi, %rax
    sub %rdx, %rax
    xor %rcx, %rax
    ret
.size hydir_expression_arithmetic64, .-hydir_expression_arithmetic64
