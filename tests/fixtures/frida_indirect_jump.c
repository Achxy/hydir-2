/* A dynamically linked Frida fixture with a real register-indirect jump. */
__asm__(
    ".text\n"
    ".globl hydir_indirect_jump\n"
    ".type hydir_indirect_jump,@function\n"
    "hydir_indirect_jump:\n"
    "  test %rdi, %rdi\n"
    "  je hydir_jump_target\n"
    "  mov %rsi, %rax\n"
    ".globl hydir_jump_site\n"
    "hydir_jump_site:\n"
    "  jmp *%rax\n"
    ".globl hydir_jump_target\n"
    "hydir_jump_target:\n"
    "  mov $7, %rax\n"
    "  ret\n"
    ".size hydir_indirect_jump, .-hydir_indirect_jump\n");

extern long hydir_indirect_jump(long flag, void *target);
extern void hydir_jump_target(void);

int main(void) {
    return hydir_indirect_jump(1, (void *)hydir_jump_target) == 7 ? 0 : 1;
}
