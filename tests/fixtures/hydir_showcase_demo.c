
#include <stdint.h>

static long sys_read(long fd, void *buffer, unsigned long count) {
    long result;
    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(0), "D"(fd), "S"(buffer), "d"(count)
        : "rcx", "r11", "memory");
    return result;
}

static long sys_write(long fd, const void *buffer, unsigned long count) {
    long result;
    __asm__ volatile (
        "syscall"
        : "=a"(result)
        : "a"(1), "D"(fd), "S"(buffer), "d"(count)
        : "rcx", "r11", "memory");
    return result;
}

__attribute__((noreturn)) static void sys_exit(long status) {
    __asm__ volatile (
        "syscall"
        :
        : "a"(60), "D"(status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

__attribute__((noinline)) uint64_t hydir_max2(uint64_t arg0, uint64_t arg1) {
    return arg0 >= arg1 ? arg0 : arg1;
}

void _start(void) {
    static const char banner[] = "HYDIR VM-STYLE CRACKME\n";
    static const char granted[] = "ACCESS GRANTED\n";
    static const char denied[] = "ACCESS DENIED\n";
    char input[4] = {0, 0, 0, 0};

    sys_write(1, banner, sizeof(banner) - 1);
    long count = sys_read(0, input, sizeof(input));
    uint64_t score = hydir_max2((uint64_t)(unsigned char)input[0], 72);

    if (count == 4 && score == 72 && input[0] == 'H' && input[1] == 'Y' &&
        input[2] == 'D' && input[3] == 'R') {
        sys_write(1, granted, sizeof(granted) - 1);
    } else {
        sys_write(1, denied, sizeof(denied) - 1);
    }

    sys_exit(0);
}
