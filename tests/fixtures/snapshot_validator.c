/* Linux x86-64 fixture; keep the declaration self-contained for syntax checks. */
extern long read(int fd, void *buffer, unsigned long count);

__attribute__((noinline, used))
int check_byte(const unsigned char *input) {
    return input[0] == (unsigned char)'A';
}

int main(void) {
    unsigned char input[2] = {0, 0};
    if (read(0, input, 1) != 1) {
        return 2;
    }
    return check_byte(input) ? 0 : 1;
}
