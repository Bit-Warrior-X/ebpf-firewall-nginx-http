/*
 * Test for the filter API
 * sudo iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
 */
/*

# Increase kernel connection tracking limits
echo 300000 > /proc/sys/net/netfilter/nf_conntrack_max
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=5400

# Increase socket buffers
sysctl -w net.core.rmem_max=4194304
sysctl -w net.core.rmem_default=2097152

# Protect against SYN floods
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_syncookies=1

 * test_conntrack.c
 *
 * Show all currently established TCP connections at startup,
 * then monitor new ESTABLISHED and DESTROY events in real time.
 * On Ctrl-C, print “Program is Closed” and exit cleanly.
 *
 * Compile with:
 *   gcc -o test_conntrack test_conntrack.c -pthread -lnetfilter_conntrack
 *
 * Run as root (or with NET_ADMIN capability):
 *   sudo ./test_conntrack
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/socket.h>           // For SO_RCVBUFFORCE

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#define MAX_EVENTS 10
#define RECOVERY_DELAY_US 1000  // 1ms
#define MAX_RETRIES 3
#define BUFFER_SIZE        (2 * 1024 * 1024)  // 2MB

#define LOG_PATH "conntrack.log"
#define LOG_I(x, args...) func_print(7, "INFO    %-*.*s:%04u   " x "" ANSI_COLOR_RESET, 30, 80, __FILE__, __LINE__, ##args)

#define ANSI_COLOR_FG_BLUE        "\x1b[0;34m"
#define ANSI_COLOR_RESET          "\x1b[0m"

static struct nfct_handle *h = NULL;
static volatile sig_atomic_t exiting = 0;
static int ct_family = AF_INET;
static size_t current_buf_size = BUFFER_SIZE;
FILE* log_file;

/* Safe print to stdout and log file */
void func_print(int id, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    time_t now = time(NULL);
    struct tm *tinfo = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tinfo);

    char out_fmt[8192];
    char buffer[10000];
    snprintf(out_fmt, sizeof(out_fmt), "%s[%s]   %s", ANSI_COLOR_FG_BLUE, timebuf, fmt);

    // Print to stdout (screen)
    va_list args_copy;
    va_copy(args_copy, args); // Create a copy of args for the second use
    vprintf(out_fmt, args);
    va_end(args); // Original args is consumed

    // Log to file if open
    if (log_file) {
        vsnprintf(buffer, sizeof(buffer), out_fmt, args_copy); // Use the copy
        fprintf(log_file, "%s", buffer);
        fflush(log_file);
    }
    va_end(args_copy); // Clean up the copy
}

/* SIGINT handler */
static void sig_handler(int signo) {
    exiting = 1;
}

/* Get timestamp string */
static const char *get_timestamp() {
    static char buf[64];
    time_t now = time(NULL);
    struct tm *tinfo = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tinfo);
    return buf;
}

/* Adjust socket receive buffer size, with force option */
static void set_socket_buffer_size(int fd, size_t size) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
        perror("setsockopt SO_RCVBUF");
#ifdef SO_RCVBUFFORCE
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0) {
            perror("setsockopt SO_RCVBUFFORCE");
        }
#endif
    }
}

/* Connection event callback */
static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data) {
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (proto != IPPROTO_TCP)
        return NFCT_CB_CONTINUE;

    uint8_t state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    if ((type == NFCT_T_NEW || type == NFCT_T_UPDATE) && state != TCP_CONNTRACK_ESTABLISHED)
        return NFCT_CB_CONTINUE;

    uint32_t sip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    uint32_t dip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    uint16_t sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    uint16_t dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

    struct in_addr in;
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    in.s_addr = sip;
    inet_ntop(AF_INET, &in, src_str, sizeof(src_str));
    in.s_addr = dip;
    inet_ntop(AF_INET, &in, dst_str, sizeof(dst_str));

    const char *type_str = (type == NFCT_T_DESTROY) ? "Destroyed" :
        (type == NFCT_T_NEW ? "New      " : "Updated  ");

    LOG_I("%s TCP %s:%u -> %s:%u (State: %d)\n",
          type_str,
          src_str, ntohs(sport),
          dst_str, ntohs(dport),
          state);

    return NFCT_CB_CONTINUE;
}

/* Thread to monitor conntrack events */
static void *conntrack_thread(void *arg) {
    struct nfct_handle *handle = (struct nfct_handle *)arg;
    int epoll_fd, nfctfd;
    struct epoll_event ev, events[MAX_EVENTS];

    nfctfd = nfct_fd(handle);

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return NULL;
    }
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.fd = nfctfd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nfctfd, &ev) < 0) {
        perror("epoll_ctl");
        close(epoll_fd);
        return NULL;
    }

    while (!exiting) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == nfctfd) {
                int ret = nfct_catch(handle);
                if (ret < 0 && errno == ENOBUFS) {
                    fprintf(stderr, "[%s] WARNING: Conntrack buffer overflow, recovering...\n", get_timestamp());
                    usleep(RECOVERY_DELAY_US);
                    current_buf_size *= 2;
                    set_socket_buffer_size(nfctfd, current_buf_size);
                    if (nfct_query(handle, NFCT_Q_DUMP, &ct_family) < 0) {
                        fprintf(stderr, "[%s] ERROR: Recovery dump failed: %s\n",
                                get_timestamp(), strerror(errno));
                    } else {
                        fprintf(stderr, "[%s] Recovery sync successful\n", get_timestamp());
                    }
                    continue;
                } else if (ret < 0) {
                    fprintf(stderr, "[%s] ERROR: nfct_catch: %s\n", get_timestamp(), strerror(errno));
                    exiting = 1;
                    break;
                }
            }
        }
    }

    close(epoll_fd);
    return NULL;
}

int main(void) {
    pthread_t ct_thread;

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("signal");
        return EXIT_FAILURE;
    }
    log_file = fopen(LOG_PATH, "a");
    if (!log_file) perror("fopen log_file");

    h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!h) {
        perror("nfct_open");
        return EXIT_FAILURE;
    }

    set_socket_buffer_size(nfct_fd(h), current_buf_size);

    if (nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL) < 0) {
        perror("nfct_callback_register");
        nfct_close(h);
        return EXIT_FAILURE;
    }

    printf("[%s] Loading existing connections...\n", get_timestamp());
    int retry = 0;
    while (retry < MAX_RETRIES) {
        if (nfct_query(h, NFCT_Q_DUMP, &ct_family) < 0) {
            if (errno == ENOBUFS) {
                fprintf(stderr, "[%s] WARNING: Initial dump buffer overflow (attempt %d/%d)\n",
                        get_timestamp(), retry+1, MAX_RETRIES);
                retry++;
                usleep(RECOVERY_DELAY_US);
                current_buf_size *= 2;
                set_socket_buffer_size(nfct_fd(h), current_buf_size);
                continue;
            }
            perror("nfct_query");
            nfct_close(h);
            return EXIT_FAILURE;
        }
        break;
    }

    printf("[%s] Now monitoring connections...\n", get_timestamp());

    if (pthread_create(&ct_thread, NULL, conntrack_thread, h) != 0) {
        perror("pthread_create");
        nfct_close(h);
        return EXIT_FAILURE;
    }

    while (!exiting) pause();

    printf("\n[%s] Shutting down...\n", get_timestamp());
    if (h) nfct_close(h);
    fclose(log_file);
    return EXIT_SUCCESS;
}