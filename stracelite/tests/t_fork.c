/* CO2 + CO3: fork, pipe, exec, wait */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
int main(void) {
    int p[2];
    pipe(p);
    pid_t c = fork();
    if (c == 0) {
        close(p[0]);
        write(p[1], "child says hi", 13);
        close(p[1]);
        execlp("echo", "echo", "exec'd in child", (char *)0);
        _exit(1);
    }
    close(p[1]);
    char b[32] = {0};
    read(p[0], b, sizeof b - 1);
    printf("parent got: %s\n", b);
    int st;
    waitpid(c, &st, 0);
    printf("child exit=%d\n", WEXITSTATUS(st));
    return 0;
}
