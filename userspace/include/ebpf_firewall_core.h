#ifndef EBPF_FIREWALL_CORE_H
#define EBPF_FIREWALL_CORE_H

int restart_fw();
int reload_fw();
int clear_fw();
int stats_fw(struct stats_config * stats);
int list_block_ip(char **out);
int clear_deny_ip(char * ip);
int clear_deny_ip_all();
int add_block_ip(char *ip, int seconds);
int list_allow_ip(char **out);
int clear_allow_ip(char * ip);
int clear_allow_ip_all();
int add_allow_ip(char *ip);

#endif