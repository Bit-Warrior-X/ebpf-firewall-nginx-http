#ifndef EBPF_FIREWALL_CONNTRACK_H
#define EBPF_FIREWALL_CONNTRACK_H

int init_conntrack(int tcp_established_fd);
void close_conntrack();

#endif