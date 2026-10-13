/* CO4: malloc/mmap, page faults, copy-on-write after fork */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    size_t big = 16 * 1024 * 1024;
    char *m = mmap(NULL, big, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (size_t i = 0; i < big; i += 4096) m[i] = 1;     /* touch -> demand paging */
    char *h = malloc(1 << 20);                            /* glibc may use brk */
    memset(h, 7, 1 << 20);
    if (fork() == 0) { m[0] = 9; _exit(0); }              /* COW fault in child */
    wait(NULL);
    munmap(m, big);
    return 0;
}
