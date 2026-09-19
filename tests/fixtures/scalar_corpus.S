/* Forty-four distinct, symbol-bounded u64(u64,u64) machine-code fixtures.
 * The validator sees only compiled ELF bytes; this source is oracle input. */
.text

.globl hydir_leaf_add
.type hydir_leaf_add,@function
hydir_leaf_add:
  mov %rdi, %rax
  add %rsi, %rax
  ret
.size hydir_leaf_add, .-hydir_leaf_add

.globl hydir_call_leaf_add
.type hydir_call_leaf_add,@function
hydir_call_leaf_add:
  sub $8, %rsp
  call hydir_leaf_add
  add $8, %rsp
  ret
.size hydir_call_leaf_add, .-hydir_call_leaf_add

.globl hydir_mov_imm64
.type hydir_mov_imm64,@function
hydir_mov_imm64:
  movabs $0xdeadbeef00000001, %rax
  ret
.size hydir_mov_imm64, .-hydir_mov_imm64

.globl hydir_cmp_imm
.type hydir_cmp_imm,@function
hydir_cmp_imm:
  mov $0, %rax
  cmp $-1, %rdi
  je .Lcmp_imm_done
  mov $1, %rax
.Lcmp_imm_done:
  ret
.size hydir_cmp_imm, .-hydir_cmp_imm

.globl hydir_test_imm
.type hydir_test_imm,@function
hydir_test_imm:
  mov $0, %rax
  test $1, %rdi
  je .Ltest_imm_done
  mov $1, %rax
.Ltest_imm_done:
  ret
.size hydir_test_imm, .-hydir_test_imm

.globl hydir_identity_a
.type hydir_identity_a,@function
hydir_identity_a:
  mov %rdi, %rax
  ret
.size hydir_identity_a, .-hydir_identity_a

.globl hydir_identity_b
.type hydir_identity_b,@function
hydir_identity_b:
  mov %rsi, %rax
  ret
.size hydir_identity_b, .-hydir_identity_b

.globl hydir_zeroextend_a
.type hydir_zeroextend_a,@function
hydir_zeroextend_a:
  mov %edi, %eax
  ret
.size hydir_zeroextend_a, .-hydir_zeroextend_a

.globl hydir_zeroextend_imm
.type hydir_zeroextend_imm,@function
hydir_zeroextend_imm:
  mov $0xffffffff, %eax
  ret
.size hydir_zeroextend_imm, .-hydir_zeroextend_imm

.globl hydir_frame_balance
.type hydir_frame_balance,@function
hydir_frame_balance:
  push %rbp
  mov %rsp, %rbp
  sub $32, %rsp
  lea (%rdi,%rsi), %rax
  add $32, %rsp
  pop %rbp
  ret
.size hydir_frame_balance, .-hydir_frame_balance

.globl hydir_stack_slot_add
.type hydir_stack_slot_add,@function
hydir_stack_slot_add:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %rdi, -8(%rbp)
  mov -8(%rbp), %rax
  add %rsi, %rax
  leave
  ret
.size hydir_stack_slot_add, .-hydir_stack_slot_add

.globl hydir_stack_branch
.type hydir_stack_branch,@function
hydir_stack_branch:
  sub $16, %rsp
  cmp %rsi, %rdi
  jae .Lstack_branch_left
  mov %rsi, (%rsp)
  jmp .Lstack_branch_join
.Lstack_branch_left:
  mov %rdi, (%rsp)
.Lstack_branch_join:
  mov (%rsp), %rax
  add $16, %rsp
  ret
.size hydir_stack_branch, .-hydir_stack_branch

.globl hydir_dword_redzone_add
.type hydir_dword_redzone_add,@function
hydir_dword_redzone_add:
  push %rbp
  mov %rsp, %rbp
  mov %edi, -4(%rbp)
  mov -4(%rbp), %eax
  add %esi, %eax
  pop %rbp
  ret
.size hydir_dword_redzone_add, .-hydir_dword_redzone_add

.globl hydir_dword_redzone_max_s
.type hydir_dword_redzone_max_s,@function
hydir_dword_redzone_max_s:
  push %rbp
  mov %rsp, %rbp
  mov %edi, -4(%rbp)
  mov %esi, -8(%rbp)
  mov -4(%rbp), %eax
  cmp -8(%rbp), %eax
  jge .Ldword_redzone_max_s_done
  mov -8(%rbp), %eax
.Ldword_redzone_max_s_done:
  pop %rbp
  ret
.size hydir_dword_redzone_max_s, .-hydir_dword_redzone_max_s

.globl hydir_nop_identity
.type hydir_nop_identity,@function
hydir_nop_identity:
  nop
  mov %rdi, %rax
  ret
.size hydir_nop_identity, .-hydir_nop_identity

.globl hydir_lea_scaled
.type hydir_lea_scaled,@function
hydir_lea_scaled:
  lea 7(%rdi,%rsi,4), %rax
  ret
.size hydir_lea_scaled, .-hydir_lea_scaled

/* Every accepted conditional branch, with CMP defining all relevant flags. */
.macro HYDIR_CONDITION suffix, jump
.globl hydir_cond_\suffix
.type hydir_cond_\suffix,@function
hydir_cond_\suffix:
  mov $0, %rax
  cmp %rsi, %rdi
  \jump .Lcondition_true\@
  ret
.Lcondition_true\@:
  mov $1, %rax
  ret
.size hydir_cond_\suffix, .-hydir_cond_\suffix
.endm

HYDIR_CONDITION e, je
HYDIR_CONDITION ne, jne
HYDIR_CONDITION g, jg
HYDIR_CONDITION ge, jge
HYDIR_CONDITION l, jl
HYDIR_CONDITION le, jle
HYDIR_CONDITION a, ja
HYDIR_CONDITION ae, jae
HYDIR_CONDITION b, jb
HYDIR_CONDITION be, jbe
HYDIR_CONDITION s, js
HYDIR_CONDITION ns, jns
HYDIR_CONDITION o, jo
HYDIR_CONDITION no, jno

.globl hydir_sub_ab
.type hydir_sub_ab,@function
hydir_sub_ab:
  mov %rdi, %rax
  sub %rsi, %rax
  ret
.size hydir_sub_ab, .-hydir_sub_ab

.globl hydir_sub_ba
.type hydir_sub_ba,@function
hydir_sub_ba:
  mov %rsi, %rax
  sub %rdi, %rax
  ret
.size hydir_sub_ba, .-hydir_sub_ba

.globl hydir_add3
.type hydir_add3,@function
hydir_add3:
  mov %rdi, %rax
  add %rsi, %rax
  add $3, %rax
  ret
.size hydir_add3, .-hydir_add3

.globl hydir_twice_a
.type hydir_twice_a,@function
hydir_twice_a:
  mov %rdi, %rax
  add %rdi, %rax
  ret
.size hydir_twice_a, .-hydir_twice_a

.globl hydir_twice_b
.type hydir_twice_b,@function
hydir_twice_b:
  mov %rsi, %rax
  add %rsi, %rax
  ret
.size hydir_twice_b, .-hydir_twice_b

.globl hydir_min_u
.type hydir_min_u,@function
hydir_min_u:
  mov %rdi, %rax
  cmp %rsi, %rdi
  jbe .Lmin_u_done
  mov %rsi, %rax
.Lmin_u_done:
  ret
.size hydir_min_u, .-hydir_min_u

.globl hydir_min_s
.type hydir_min_s,@function
hydir_min_s:
  mov %rdi, %rax
  cmp %rsi, %rdi
  jle .Lmin_s_done
  mov %rsi, %rax
.Lmin_s_done:
  ret
.size hydir_min_s, .-hydir_min_s

.globl hydir_equal
.type hydir_equal,@function
hydir_equal:
  mov $0, %rax
  cmp %rsi, %rdi
  jne .Lequal_done
  mov $1, %rax
.Lequal_done:
  ret
.size hydir_equal, .-hydir_equal

.globl hydir_not_equal
.type hydir_not_equal,@function
hydir_not_equal:
  mov $0, %rax
  cmp %rsi, %rdi
  je .Lnot_equal_done
  mov $1, %rax
.Lnot_equal_done:
  ret
.size hydir_not_equal, .-hydir_not_equal

.globl hydir_less_u
.type hydir_less_u,@function
hydir_less_u:
  mov $0, %rax
  cmp %rsi, %rdi
  jae .Lless_u_done
  mov $1, %rax
.Lless_u_done:
  ret
.size hydir_less_u, .-hydir_less_u

.globl hydir_less_s
.type hydir_less_s,@function
hydir_less_s:
  mov $0, %rax
  cmp %rsi, %rdi
  jge .Lless_s_done
  mov $1, %rax
.Lless_s_done:
  ret
.size hydir_less_s, .-hydir_less_s

.globl hydir_bit_overlap
.type hydir_bit_overlap,@function
hydir_bit_overlap:
  mov $0, %rax
  test %rsi, %rdi
  je .Lbit_overlap_done
  mov $1, %rax
.Lbit_overlap_done:
  ret
.size hydir_bit_overlap, .-hydir_bit_overlap

.globl hydir_repeat3
.type hydir_repeat3,@function
hydir_repeat3:
  mov $0, %rax
  mov $3, %rcx
.Lrepeat3_loop:
  add %rdi, %rax
  sub $1, %rcx
  jne .Lrepeat3_loop
  ret
.size hydir_repeat3, .-hydir_repeat3

.globl hydir_repeat4
.type hydir_repeat4,@function
hydir_repeat4:
  mov $0, %rax
  mov $4, %rcx
.Lrepeat4_loop:
  add %rsi, %rax
  sub $1, %rcx
  jne .Lrepeat4_loop
  ret
.size hydir_repeat4, .-hydir_repeat4

.section .note.GNU-stack,"",@progbits
