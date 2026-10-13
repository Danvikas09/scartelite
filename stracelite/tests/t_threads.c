/* CO6: threads + mutex (futex syscalls show contention) */
#include <stdio.h>
#include <pthread.h>
static long counter; static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static void *w(void *a) { for (int i = 0; i < 100000; i++) { pthread_mutex_lock(&mu); counter++; pthread_mutex_unlock(&mu); } return 0; }
int main(void) {
    pthread_t t[3];
    for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, w, 0);
    for (int i = 0; i < 3; i++) pthread_join(t[i], 0);
    printf("counter=%ld\n", counter);
    return 0;
}
