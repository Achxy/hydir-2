.text
.globl hydir_expression_widths
.type hydir_expression_widths,@function
hydir_expression_widths:
    mov %edi, %eax
    mov %bl, %ah
    mov %cl, %al
    add %edx, %eax
    ret
.size hydir_expression_widths, .-hydir_expression_widths
