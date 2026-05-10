#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>

// global variable modified by signal handlers
volatile sig_atomic_t running = 1;


// SIGINT handler
void handle_sigint(int sig) {
    const char *msg = "\nMonitor shutting down...\n";

    write(STDOUT_FILENO, msg, strlen(msg));

    running = 0;
}


// SIGUSR1 handler
void handle_sigusr1(int sig) {
    const char *msg = "New report added.\n";

    write(STDOUT_FILENO, msg, strlen(msg));
}


int main() {

    // CREATE / OVERWRITE .monitor_pid

    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd == -1) {
        perror("open .monitor_pid");
        return 1;
    }

    pid_t pid = getpid();

    char buffer[50];

    int len = snprintf(buffer, sizeof(buffer), "%d\n", pid);

    if (write(fd, buffer, len) != len) {
        perror("write pid");
        close(fd);
        return 1;
    }

    close(fd);


    // INSTALL SIGINT HANDLER

    struct sigaction sa_int;

    sa_int.sa_handler = handle_sigint;

    sigemptyset(&sa_int.sa_mask);

    sa_int.sa_flags = 0;

    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("sigaction SIGINT");
        return 1;
    }


    // INSTALL SIGUSR1 HANDLER

    struct sigaction sa_usr1;

    sa_usr1.sa_handler = handle_sigusr1;

    sigemptyset(&sa_usr1.sa_mask);

    sa_usr1.sa_flags = 0;

    if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1) {
        perror("sigaction SIGUSR1");
        return 1;
    }


    printf("Monitor started. PID = %d\n", pid);


    // WAIT FOREVER UNTIL SIGINT

    while (running) {
        pause();
    }


    // CLEANUP

    if (unlink(".monitor_pid") == -1) {
        perror("unlink .monitor_pid");
        return 1;
    }

    return 0;
}