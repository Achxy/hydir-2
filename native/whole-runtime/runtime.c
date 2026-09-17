/* Linux x86-64, freestanding guest-memory bridge for the restricted lift.
 * The only host operations are read, write, exit. Invalid guest access exits
 * 126. It is a semantic bridge, NOT an adversarial sandbox. */
#include <stdint.h>

extern unsigned char hydir_memory[];
extern const unsigned char hydir_owned[];
extern const unsigned char hydir_writable[];
extern const uint64_t hydir_guest_base;
extern const uint64_t hydir_memory_len;

static __attribute__((noreturn)) void exit_raw(uint64_t code) {
  __asm__ volatile("syscall" : : "a"(60UL), "D"(code) : "rcx", "r11", "memory");
  __builtin_unreachable();
}

void hydir_trap(void) { exit_raw(125); }

static void *translate(uint64_t address, uint64_t length, int is_read) {
  if (address < hydir_guest_base || length > hydir_memory_len ||
      address - hydir_guest_base > hydir_memory_len - length)
    return (void *)0;
  uint64_t offset = address - hydir_guest_base;
  for (uint64_t i = 0; i < length; ++i)
    if (!hydir_owned[offset + i] || (is_read && !hydir_writable[offset + i]))
      return (void *)0;
  return hydir_memory + offset;
}

uint64_t hydir_syscall(uint64_t number, uint64_t arg0, uint64_t arg1,
                       uint64_t arg2) {
  if (number == 60) exit_raw(arg0);
  if (number != 0 && number != 1) exit_raw(126);
  void *buffer = translate(arg1, arg2, number == 0);
  if (!buffer) return (uint64_t)-14; /* Linux EFAULT */
  uint64_t result;
  __asm__ volatile("syscall" : "=a"(result)
                   : "a"(number), "D"(arg0), "S"(buffer), "d"(arg2)
                   : "rcx", "r11", "memory");
  return result;
}
