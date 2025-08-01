// gcc -o firewall_cli firewall_cli.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/ebpf_fw.sock"
#define BUF_SZ    1024

static void usage(void) {
    fputs(
"Usage: firewall_cli COMMAND [args]\n"
"Commands:\n"
"  RESTART_FW : Restart the firewall\n"
"  RELOAD_FW : Reload the firewall config\n"
"  CLEAR_FW : Clear all packet statistics. (Reset all statistics as zero).\n"
"  STATS_FW : Display all packet information captured. (SYN, ACK, RST, PSH, FIN, URG, SYN+ACK, FIN+ACK, RST+ACK, ICMP UDP, GRE)\n"
"  LIST_BLOCK_IP : Dump current blacklist ip. (ip expire_ns per line)\n"
"  CLEAR_BLOCK_IP <ip> : Remove ip from blacklist\n"
"  CLEAR_BLOCK_IP_ALL : Remove all ips from blacklist\n"
"  ADD_BLOCK_IP <ip> [seconds] : Add ip to blacklist. Default duration if seconds omitted.\n"
"  LIST_ALLOW_IP : Dump whitelist ip list\n"
"  CLEAR_ALLOW_IP <ip> : Remove ip from whitelist\n"
"  CLEAR_ALLOW_IP_ALL : Remove all ips from blacklist\n"
"  ADD_ALLOW_IP <ip> : Add ip to whitelist.\n", stderr);
    exit(EXIT_FAILURE);
}

static int send_and_print(const char *msg) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) { perror("socket"); return 2; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
        perror("connect"); close(fd); return 2;
    }

    size_t len = strlen(msg);
    if (write(fd, msg, len) != (ssize_t)len) { perror("write"); close(fd); return 2; }

    char buf[BUF_SZ];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) {
            if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) {
                perror("fwrite");
                close(fd);
                return 2;
            }
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        perror("read");
        close(fd);
        return 2;
    }
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage();

    /* Build the outgoing line */
    char line[BUF_SZ] = {0};
    size_t pos = 0;
    for (int i = 1; i < argc; ++i) {
        pos += snprintf(line + pos, sizeof line - pos, "%s%s",
                        i == 1 ? "" : " ", argv[i]);
        if (pos >= sizeof line - 2) { fputs("command too long\n", stderr); return 2; }
    }
    strcat(line, "\n");

    return send_and_print(line);
}