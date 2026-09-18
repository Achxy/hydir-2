/*
 * HydIR Access Gate: a deliberately transparent, freestanding ELF demo.
 *
 * This is not a real authentication mechanism.  Its purpose is to provide
 * readable named functions, calls, loops, and decision diamonds for HydIR's
 * disassembly, CFG, call-graph, and symbolic-analysis demonstrations.
 *
 * Build on Linux x86-64 (or with a cross-capable Clang):
 *   clang --target=x86_64-unknown-linux-gnu -O1 -fno-stack-protector \
 *     -fno-builtin -nostdlib -no-pie -Wl,--build-id=none -Wl,-e,_start \
 *     tests/fixtures/hydir_password_demo.c -o hydir-password-gate.elf
 */

typedef unsigned char u8;
typedef unsigned long u64;
typedef long i64;

#define NOINLINE __attribute__((noinline, used))

static const char banner[] =
    "\n"
    "  _   _ __   ______  ___ ____\n"
    " | | | |\\ \\ / /  _\\/ _ \\|  _ \\\n"
    " | |_| |\\ V /| | | | | | | |_) |   ACCESS GATE // ELF DEMO\n"
    "  \\___/  |_| |_| |_| |_| |_|  _/\n"
    "                         |_|     graph-friendly control flow\n\n";
static const char prompt[] = "  Enter access phrase: ";
static const char meter_low[] = "  SIGNAL  [##--------] low entropy\n";
static const char meter_mid[] = "  SIGNAL  [#####-----] candidate route\n";
static const char meter_high[] = "  SIGNAL  [########--] high entropy\n";
static const char meter_elite[] = "  SIGNAL  [##########] elite entropy\n";
static const char granted[] = "  >>> ACCESS GRANTED :: welcome to HydIR <<<\n";
static const char review[] = "  >>> MATCHED, BUT POLICY REVIEW REQUIRED <<<\n";
static const char denied[] = "  >>> ACCESS DENIED :: trace captured <<<\n";
static const char lockout[] = "  >>> ACCESS DENIED :: suspicious high-score decoy <<<\n";

static u8 input[48];
static const u8 access_phrase[] = "HYDIR-ACCESS";

static i64 sys_write(const char *bytes, u64 length) {
    i64 result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(1UL), "D"(1UL), "S"(bytes), "d"(length)
        : "rcx", "r11", "memory");
    return result;
}

static i64 sys_read(u8 *bytes, u64 length) {
    i64 result;
    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(0UL), "D"(0UL), "S"(bytes), "d"(length)
        : "rcx", "r11", "memory");
    return result;
}

static void sys_exit(u64 status) {
    __asm__ volatile(
        "syscall"
        :
        : "a"(60UL), "D"(status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

NOINLINE u64 hydir_mix64(u64 value, u64 salt) {
    value ^= salt + 0x9e3779b97f4a7c15UL;
    value = (value << 13) | (value >> 51);
    value *= 0xbf58476d1ce4e5b9UL;
    return value ^ (value >> 29);
}

/*
 * The one-click Triton showcase.  Keep this deliberately small: Clang emits
 * `lea rax, [rdi+rsi]; ret`, giving the bounded bridge an immediately useful
 * symbolic result: rax = arg0 + arg1.
 */
NOINLINE u64 hydir_triton_add2(u64 arg0, u64 arg1) {
    return arg0 + arg1;
}

NOINLINE u64 hydir_password_score(const u8 *bytes, u64 length) {
    u64 score = 0;
    u64 lane = 0x48445949522d4445UL;
    u64 index;

    for (index = 0; index < length; ++index) {
        u8 ch = bytes[index];
        lane = hydir_mix64(lane ^ ch, index + 0x31UL);
        if (ch >= 'A' && ch <= 'Z') {
            score += 7;
        } else if (ch >= '0' && ch <= '9') {
            score += 5;
        } else if (ch == '-' || ch == '_') {
            score += 9;
        } else {
            score += 2;
        }
    }

    return score + (lane & 0x0fUL);
}

NOINLINE int hydir_secure_equals(const u8 *bytes, u64 length) {
    u8 difference = 0;
    u64 index;

    if (length != sizeof(access_phrase) - 1) {
        return 0;
    }
    for (index = 0; index < sizeof(access_phrase) - 1; ++index) {
        difference |= bytes[index] ^ access_phrase[index];
    }
    return difference == 0;
}

NOINLINE void hydir_emit_meter(u64 score) {
    if (score >= 104) {
        sys_write(meter_elite, sizeof(meter_elite) - 1);
    } else if (score >= 76) {
        sys_write(meter_high, sizeof(meter_high) - 1);
    } else if (score >= 42) {
        sys_write(meter_mid, sizeof(meter_mid) - 1);
    } else {
        sys_write(meter_low, sizeof(meter_low) - 1);
    }
}

NOINLINE u64 hydir_policy_route(u64 score, int matched) {
    hydir_emit_meter(score);
    if (matched && score >= 70) {
        sys_write(granted, sizeof(granted) - 1);
        return 0;
    }
    if (matched) {
        sys_write(review, sizeof(review) - 1);
        return 2;
    }
    if (score >= 100) {
        sys_write(lockout, sizeof(lockout) - 1);
        return 3;
    }
    sys_write(denied, sizeof(denied) - 1);
    return 1;
}

void _start(void) {
    i64 read_count;
    u64 length;
    u64 score;
    int matched;

    sys_write(banner, sizeof(banner) - 1);
    sys_write(prompt, sizeof(prompt) - 1);
    read_count = sys_read(input, sizeof(input));
    if (read_count <= 0) {
        sys_write(denied, sizeof(denied) - 1);
        sys_exit(1);
    }

    length = (u64)read_count;
    if (input[length - 1] == '\n') {
        --length;
    }
    score = hydir_password_score(input, length);
    matched = hydir_secure_equals(input, length);
    sys_exit(hydir_policy_route(score, matched));
}
