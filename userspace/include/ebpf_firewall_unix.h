#ifndef EBPF_FIREWALL_UNIX_H
#define EBPF_FIREWALL_UNIX_H

int init_unix_socket();
void close_unix_socket();

int init_unix_nginx_socket();
void close_unix_nginx_socket();
#endif