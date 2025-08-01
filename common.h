#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Define time constants (in nanoseconds)

#define MAX_LINE_LEN                128
#define XDP_CORE_FILE               "ebpf_firewall_kernel.o"
#define CONFIG_FILE                 "firewall.config"
#define SOCK_PATH                   "/tmp/ebpf_fw.sock"

#define ONE_SECOND_NS               1000000000ULL
#define BLOCK_DURATION_NS           (3600ULL * 1000000000ULL)  // 1 hour

#define SYN_THRESHOLD               200000                    // 200K SYN packets per second
#define SYN_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 SYN packets */
#define SYN_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define SYN_FIXED_THRESHOLD         20000                     // Maximum SYN packets allowed in a 15-second window.
#define SYN_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define SYN_CHALLENGE_TIMEOUT_NS    (2ULL * ONE_SECOND_NS)    // Timeout for challenge state
#define SYN_BURST_GAP_NS            ONE_SECOND_NS / SYN_BURST_COUNT_THRESHOLD    /* 100 ms gap ends a burst */
#define SYN_PROTECTION_DURATION     0                         // Protection duration for SYN

#define ACK_THRESHOLD               200000                    // 200K ACK packets per second
#define ACK_BURST_COUNT_THRESHOLD   100                       /* 10 bursts per second triggers block */
#define ACK_BURST_PKT_THRESHOLD     200                       /* Each burst must have >=20 ACK packets */
#define ACK_FIXED_THRESHOLD         20000                     // Maximum ACK packets allowed in a 15-second window.
#define ACK_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define ACK_BURST_GAP_NS            ONE_SECOND_NS / ACK_BURST_PKT_THRESHOLD     
#define ACK_PROTECTION_DURATION     0                         // Protection duration for ACK

#define RST_THRESHOLD               200000                    // 200K RST packets per second
#define RST_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define RST_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 RST packets */
#define RST_FIXED_THRESHOLD         20000                     // Maximum RST packets allowed in a 15-second window.
#define RST_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define RST_BURST_GAP_NS            ONE_SECOND_NS / RST_BURST_PKT_THRESHOLD 
#define RST_PROTECTION_DURATION     0                         // Protection duration for RST

#define ICMP_THRESHOLD               200000                    // 200K ICMP packets per second
#define ICMP_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define ICMP_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 ICMP packets */
#define ICMP_FIXED_THRESHOLD         20000                     // Maximum ICMP packets allowed in a 15-second window.
#define ICMP_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define ICMP_BURST_GAP_NS            ONE_SECOND_NS / ICMP_BURST_PKT_THRESHOLD
#define ICMP_PROTECTION_DURATION     0                         // Protection duration for ICMP

#define UDP_THRESHOLD               200000                     // 200K ICMP packets per second
#define UDP_BURST_COUNT_THRESHOLD   10                         /* 10 bursts per second triggers block */
#define UDP_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 UDP packets */
#define UDP_FIXED_THRESHOLD         20000                      // Maximum UDP packets allowed in a 15-second window.
#define UDP_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)    // 15 seconds for fixed duration check
#define UDP_BURST_GAP_NS            ONE_SECOND_NS / UDP_BURST_PKT_THRESHOLD
#define UDP_PROTECTION_DURATION     0                         // Protection duration for UDP

#define GRE_THRESHOLD               200000                     // 200K GRE packets per second
#define GRE_BURST_COUNT_THRESHOLD   10                         /* bursts per sec */
#define GRE_BURST_PKT_THRESHOLD     20                         /* Each burst must have >=20 GRE packets */
#define GRE_FIXED_THRESHOLD         20000                      // 15‑sec window
#define GRE_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)
#define GRE_BURST_GAP_NS            ONE_SECOND_NS / GRE_BURST_PKT_THRESHOLD
#define GRE_PROTECTION_DURATION     0                         // Protection duration for GRE

#define EVENT_IP_BLOCK_END                         0
#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START  10
#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END    11
#define EVENT_TCP_SYN_ATTACK_BURST_BLOCK           12
#define EVENT_TCP_SYN_ATTACK_FIXED_BLOCK           13

#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START  20
#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END    21
#define EVENT_TCP_ACK_ATTACK_BURST_BLOCK           22
#define EVENT_TCP_ACK_ATTACK_FIXED_BLOCK           23

#define EVENT_TCP_RST_ATTACK_PROTECION_MODE_START  30
#define EVENT_TCP_RST_ATTACK_PROTECION_MODE_END    31
#define EVENT_TCP_RST_ATTACK_BURST_BLOCK           32
#define EVENT_TCP_RST_ATTACK_FIXED_BLOCK           33

#define EVENT_ICMP_ATTACK_PROTECION_MODE_START     40
#define EVENT_ICMP_ATTACK_PROTECION_MODE_END       41
#define EVENT_ICMP_ATTACK_BURST_BLOCK              42
#define EVENT_ICMP_ATTACK_FIXED_BLOCK              43

#define EVENT_UDP_ATTACK_PROTECION_MODE_START      50
#define EVENT_UDP_ATTACK_PROTECION_MODE_END        51
#define EVENT_UDP_ATTACK_BURST_BLOCK               52
#define EVENT_UDP_ATTACK_FIXED_BLOCK               53

#define EVENT_GRE_ATTACK_PROTECION_MODE_START      60
#define EVENT_GRE_ATTACK_PROTECION_MODE_END        61
#define EVENT_GRE_ATTACK_BURST_BLOCK               62
#define EVENT_GRE_ATTACK_FIXED_BLOCK               63

// >>> New event for Fragment attack <<<
#define EVENT_IP_FRAG_MIDDLE_BLOCK                 70


#define FIXED_IP_RING_BUF_SYN                      1
#define FIXED_IP_RING_BUF_ACK                      2
#define FIXED_IP_RING_BUF_RST                      3
#define FIXED_IP_RING_BUF_PSH                      4
#define FIXED_IP_RING_BUF_URG                      5
#define FIXED_IP_RING_BUF_FIN                      6
#define FIXED_IP_RING_BUF_SYN_ACK                  7
#define FIXED_IP_RING_BUF_RST_ACK                  8
#define FIXED_IP_RING_BUF_FIN_ACK                  9
#define FIXED_IP_RING_BUF_UDP                      10
#define FIXED_IP_RING_BUF_ICMP                     11
#define FIXED_IP_RING_BUF_GRE                      12

struct global_config {
    __u8 tcp_seg_check;
    __u64 black_ip_duration;     // Blacklist duration in seconds
};

struct event {
    __u64 time;
    __u16 reason;
    __u32 srcip;
};

struct fixed_ip_event {
    __u32 srcip;
    __u16 fixed_type;
    __u64 duration;
    __u64 pkt_count;
    __u8 over_fixed;
};

// Existing counters for flood detection.
struct flood_stats {
    __u8  detected;
    __u64 count;
    __u64 last_ts;
};

struct global_attack_stats {
    __u8 syn_attack;    
    __u64 syn_protect_expire;
    __u8 ack_attack;
    __u64 ack_protect_expire;
    __u8 rst_attack ;
    __u64 rst_protect_expire;
    __u8 icmp_attack;
    __u64 icmp_protect_expire;
    __u8 udp_attack;
    __u64 udp_protect_expire;
    __u8 gre_attack;
    __u64 gre_protect_expire;
};

// Per-source state for SYN packet bursts.
struct burst_state {
    __u64 last_pkt_time;       /* Timestamp of the last SYN packet */
    __u32 current_burst_count; /* Count of SYN packets in current burst */
    __u32 burst_count;         /* Number of bursts (which met the threshold) in current 1s window */
    __u64 last_reset;          /* Start time of the current 1-second window */
};

struct syn_config {
    __u32 syn_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u64 challenge_timeout;
    __u32 syn_fixed_threshold;
    __u64 syn_fixed_check_duration;
    __u32 syn_protect_duration;
};

struct ack_config {
    __u32 ack_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 ack_fixed_threshold;
    __u64 ack_fixed_check_duration;
    __u32 ack_protect_duration;
};

struct rst_config {
    __u32 rst_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 rst_fixed_threshold;
    __u64 rst_fixed_check_duration;
    __u32 rst_protect_duration;
};

struct icmp_config {
    __u32 icmp_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 icmp_fixed_threshold;
    __u64 icmp_fixed_check_duration;
    __u32 icmp_protect_duration;
};

struct udp_config {
    __u32 udp_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 udp_fixed_threshold;
    __u64 udp_fixed_check_duration;
    __u32 udp_protect_duration;
};

struct gre_config {
    __u32 gre_threshold;
    __u64 burst_gap_ns;
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 gre_fixed_threshold;
    __u64 gre_fixed_check_duration;
    __u32 gre_protect_duration;
};


struct global_firewall_config {
    struct global_attack_stats g_attack_stats;
    struct global_config       g_config;
    struct syn_config          g_syn_config;
    struct ack_config          g_ack_config;
    struct rst_config          g_rst_config;
    struct icmp_config         g_icmp_config;
    struct udp_config          g_udp_config;
    struct gre_config          g_gre_config;
};

// New structure and map for the SYN challenge state.
struct challenge_state {
    __u8 stage;       // 1: first SYN seen; 2: challenge sent (waiting for client response)
    __u64 ts;         // Timestamp when state was updated
    __u32 seq;        // Seq Number of syn
};

struct icmphdr
{
  __u8 type;                /* message type */
  __u8 code;                /* type sub-code */
  __u16 checksum;
  union
  {
    struct
    {
      __u16        id;
      __u16        sequence;
    } echo;                        /* echo datagram */
    __u32        gateway;        /* gateway address */
    struct
    {
      __u16        __unused;
      __u16        mtu;
    } frag;                        /* path mtu discovery */
  } un;
};

struct stats_config {
    __u64 syn;
    __u64 ack;
    __u64 rst;

    __u64 urg;
    __u64 psh;
    __u64 fin;

    __u64 syn_ack;
    __u64 fin_ack;
    __u64 rst_ack;
    
    __u64 icmp;
    __u64 udp;
    __u64 gre;
};


struct fixed_ip_pkt_stats {
    __u64 normal_syn;
    __u64 attack_syn;

    __u64 normal_ack;
    __u64 attack_ack;

    __u64 normal_rst;
    __u64 attack_rst;

    __u64 normal_urg;
    __u64 attack_urg;

    __u64 normal_psh;
    __u64 attack_psh;

    __u64 normal_fin;
    __u64 attack_fin;

    __u64 normal_syn_ack;
    __u64 attack_syn_ack;

    __u64 normal_fin_ack;
    __u64 attack_fin_ack;

    __u64 normal_rst_ack;
    __u64 attack_rst_ack;

    __u64 normal_icmp;
    __u64 attack_icmp;

    __u64 normal_udp;
    __u64 attack_udp;
    
    __u64 normal_gre;
    __u64 attack_gre;
};


//}  __attribute__((aligned(8)));

#endif