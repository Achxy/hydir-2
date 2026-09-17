/* Sixteen distinct, symbol-bounded u64(u64,u64) machine-code fixtures.
 * The validator sees only compiled ELF bytes; this source is oracle input. */
.text

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
