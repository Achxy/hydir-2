#include <stdio.h>
#include <signal.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "crash") == 0) {
        raise(SIGSEGV);
        return 99;
    }
    char line[16] = {0};
    char key[4] = {0};
    FILE *file = fopen("data/key", "rb");
    int file_ok = file != NULL && fread(key, 1, 3, file) == 3;
    if (file != NULL) {
        fclose(file);
    }
    if (argc == 2 && strcmp(argv[1], "open") == 0
        && fgets(line, sizeof(line), stdin) != NULL
        && strcmp(line, "secret\n") == 0
        && file_ok && memcmp(key, "key", 3) == 0) {
        puts("ACCESS GRANTED");
        return 0;
    }
    puts("DENIED");
    return 1;
}
