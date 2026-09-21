.text

.globl hydir_copy_bytes
.type hydir_copy_bytes,@function
hydir_copy_bytes:
    movq %rdx, %rcx
    cld
    rep movsb
    retq
.size hydir_copy_bytes, .-hydir_copy_bytes

.globl hydir_fill_qwords
.type hydir_fill_qwords,@function
hydir_fill_qwords:
    movq %rsi, %rax
    movq %rdx, %rcx
    cld
    rep stosq
    retq
.size hydir_fill_qwords, .-hydir_fill_qwords

.globl hydir_equal_bytes
.type hydir_equal_bytes,@function
hydir_equal_bytes:
    movq %rdx, %rcx
    cld
    repe cmpsb
    sete %al
    retq
.size hydir_equal_bytes, .-hydir_equal_bytes

.globl hydir_find_byte
.type hydir_find_byte,@function
hydir_find_byte:
    movq %rsi, %rax
    movq %rdx, %rcx
    cld
    repne scasb
    sete %al
    retq
.size hydir_find_byte, .-hydir_find_byte

.section .note.GNU-stack,"",@progbits
