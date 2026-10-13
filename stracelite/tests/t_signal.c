/* CO3: signal handler, kill self, alarm */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
static void h(int s) { write(1, "caught signal\n", 14); }
int main(void) {
    struct sigaction sa = { .sa_handler = h };
    sigaction(SIGUSR1, &sa, NULL);
    kill(getpid(), SIGUSR1);
    raise(SIGTERM);            /* default action: terminate */
    return 0;
}
