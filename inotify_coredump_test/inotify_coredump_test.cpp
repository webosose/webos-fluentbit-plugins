#include <stdio.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

int main(int argc, char *argv[])
{
    char *watchDir = (argc == 1) ? (char*)"/var/lib/systemd/coredump" : argv[1];

    char buffer[BUF_LEN];

    int fd = inotify_init();
    if (-1 == fd) {
        perror("inotify_init");
        return 0;
    }

    printf("Watch dir %s\n", watchDir);
    int wd = inotify_add_watch(fd, watchDir, IN_ALL_EVENTS);
    if (-1 == wd) {
        perror("inotify_add_watch");
        close(fd);
        return 0;
    }

    while (true) {
        ssize_t nRead = read(fd, buffer, BUF_LEN);
        if (-1 == nRead) {
            perror("read");
            break;
        }

        for (int pos = 0; pos < nRead; ) {
            struct inotify_event *event = (struct inotify_event *) &buffer[pos];
            printf("nRead=[%3d], pos=[%3d], mask=[%8x], len=[%2d]", nRead, pos, event->mask, event->len);
            if (event->len > 0)
                printf(", name=[%s]\n", event->name);
            else
                printf("\n");
            pos += EVENT_SIZE + event->len;
        }
    }

    if (-1 == inotify_rm_watch(fd, wd)) {
        perror("inotify_rm_watch");
    }
    close(fd);
    return 0;
}
