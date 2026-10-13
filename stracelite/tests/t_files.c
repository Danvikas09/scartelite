/* CO5: file I/O - create, write, read, stat, unlink */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int fd = open("/tmp/slite_demo.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    const char *msg = "hello from StraceLite\n";
    write(fd, msg, strlen(msg));
    close(fd);
    char buf[64];
    fd = open("/tmp/slite_demo.txt", O_RDONLY);
    int n = read(fd, buf, sizeof buf);
    write(1, buf, n);
    close(fd);
    open("/no/such/file", O_RDONLY);          /* deliberate ENOENT */
    unlink("/tmp/slite_demo.txt");
    return 0;
}
