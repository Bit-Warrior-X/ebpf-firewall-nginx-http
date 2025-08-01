// xdp_prog.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

volatile struct global_firewall_config global_fw_config SEC(".bss");

/* Tail call map: keys will be used to jump to parse functions.
 * Key 0 -> xdp_parse_syn, 
   Key 1 -> xdp_parse_ack.
   Key 2 -> xdp_parse_rst.
   Key 3 -> xdp_parse_icmp.
   Key 4 -> xdp_parse_udp.
   Key 5 -> xdp_parse_gre.
 */

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
    __type(key, __u32);             // Source IP address.
    __type(value, __u64);           // Block expiration time (ns)
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);     /* 256KB buffer */
} ring_buf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);     /* 64MB buffer */
} fixed_ip_ring_buf_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);             // Source IP address.
    __type(value, __u8);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);   // Source IP address + Port.
    __type(value, __u8);  // Temp value.
} tcp_established_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_config);
} global_income_pkt_counter SEC(".maps");


/*-------------------------------------------- Static Functions ------------------------------------*/
static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
/*--------------------------------------------------------------------------------------------------*/

/*---------------------------------------------- XDP Main ------------------------------------------*/
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();
    
    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only handle IP packets.
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header.
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;
    
    __u32 key = 0;
    struct stats_config *pkt_stats = bpf_map_lookup_elem(&global_income_pkt_counter, &key);
    if (!pkt_stats) return XDP_PASS;

    // Handle TCP packets
    if (iph->protocol == IPPROTO_TCP) {
        // Calculate IP header length.
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void*)(tcph + 1) <= data_end) {
            // If SYN flag is set and ACK flag is not set, then it's a SYN packet.
            if (tcph->syn && !tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->syn, 1);
            }
            // If RST is set.
            if (tcph->rst && !tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->rst, 1);
            }
            // If URG is set.
            if (tcph->urg && !tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->urg, 1);
            }
            // If PSH is set.
            if (tcph->psh && !tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->psh, 1);
            }
            // If PSH is set.
            if (tcph->fin && !tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->fin, 1);
            }
            // If ACK is set, excluding SYN, FIN, RST.
            if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
                __sync_fetch_and_add(&pkt_stats->ack, 1);
            }
            // If SYN+ACK is set.
            if (tcph->syn && tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->syn_ack, 1);
            }
            // If FIN+ACK is set.
            if (tcph->fin && tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->fin_ack, 1);
            }
            // If RST+ACK is set.
            if (tcph->rst && tcph->ack) {
                __sync_fetch_and_add(&pkt_stats->rst_ack, 1);
            }
        }
    }
    // Handle ICMP packets
    else if (iph->protocol == IPPROTO_ICMP) {
        __sync_fetch_and_add(&pkt_stats->icmp, 1);
    }
    // Handle UDP packets
    else if (iph->protocol == IPPROTO_UDP) {
        __sync_fetch_and_add(&pkt_stats->udp, 1);
    }
    // Handle GRE packets
    else if (iph->protocol == IPPROTO_GRE) {
        __sync_fetch_and_add(&pkt_stats->gre, 1);
    }

     __u32 src_ip = iph->saddr;

    /* Whitelist check: if source IP is in allowed_ips, bypass all other checks */
    __u8 *whitelisted = bpf_map_lookup_elem(&allowed_ips, &src_ip);
    if (whitelisted) {
        return XDP_PASS;
    }

    __u64 *blocked_exp = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked_exp) {
        if (now < *blocked_exp)
            return XDP_DROP;
        else {
            //bpf_printk("IP %pI4 removed from block list\n", &src_ip);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_IP_BLOCK_END;
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            bpf_map_delete_elem(&blocked_ips, &src_ip);
        }
    }

    /* -------------------- Fragment attack mitigation -------------------- */
    /* If this packet is a non-initial fragment (offset > 0), drop it directly.
       Such middle fragments lack L4 headers and can be easily used to exhaust the reassembly buffer. Regular traffic rarely has a single offset>0 fragment. */

    volatile struct global_config *global_config_val = &global_fw_config.g_config;
    if (global_config_val->tcp_seg_check) {
        __u16 frag_off_host = bpf_ntohs(iph->frag_off);
        if (frag_off_host & 0x1FFF) {                 /* Fragment offset ≠ 0 */
            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_IP_FRAG_MIDDLE_BLOCK;
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
            return XDP_DROP;
        }
    }

    // Handle TCP packets
    if (iph->protocol == IPPROTO_TCP) {
        // Calculate IP header length.
        int ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (void *)iph + ip_hdr_len;
        if ((void*)(tcph + 1) > data_end)
            return XDP_PASS;

        // Check TCP flags:
        // If SYN flag is set and ACK flag is not set, then it's a SYN packet.
        if (tcph->syn && !tcph->ack) {
            // Tail call to xdp_parse_syn (map key 0).
            bpf_tail_call(ctx, &prog_array, 0);
        }
        // If ACK is set, excluding SYN, FIN, RST.
        if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
            // Tail call to xdp_parse_ack (map key 1).
            bpf_tail_call(ctx, &prog_array, 1);
        }
        // If RST is set.
        if (tcph->rst && !tcph->ack) {
            // Tail call to xdp_parse_ack (map key 2).
            bpf_tail_call(ctx, &prog_array, 2);
        }
    }
    // Handle ICMP packets
    else if (iph->protocol == IPPROTO_ICMP) {
        // Calculate IP header length.
        int ip_hdr_len = iph->ihl * 4;
        struct icmphdr *icmph = (void *)iph + ip_hdr_len;
        if ((void*)(icmph + 1) > data_end)
            return XDP_PASS;
        bpf_tail_call(ctx, &prog_array, 3);
    }
    // Handle UDP packets
    else if (iph->protocol == IPPROTO_UDP) {
        // Calculate IP header length.
        int ip_hdr_len = iph->ihl * 4;
        struct udphdr *udphdr = (void *)iph + ip_hdr_len;
        if ((void*)(udphdr + 1) > data_end)
            return XDP_PASS;
        bpf_tail_call(ctx, &prog_array, 4);
    }
    // Handle GRE packets
    else if (iph->protocol == IPPROTO_GRE) {
        bpf_tail_call(ctx, &prog_array, 5);
    }
    
    // If tail call fails or packet does not match above criteria,
    // then pass the packet.
    return XDP_PASS;
}

/*---------------------------------------------- XDP SYN Defense ------------------------------------------*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_syn_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} syn_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} syn_counter_fixed_metrics SEC(".maps");

/* Map for per-source state: key: source IP (in network byte order), value: burst_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_syn_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);             // Source IP address.
    __type(value, struct challenge_state);
} syn_challenge SEC(".maps");

SEC("xdp")
int xdp_parse_syn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header.
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    
    __u32 key = 0;

    volatile struct global_config *global_config_val = &global_fw_config.g_config;

    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    //__u32 dst_ip = ip->daddr;
    //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

    // Get current threshold from map
    volatile struct syn_config *config = &global_fw_config.g_syn_config;

    key = 0;
    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_syn_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;
    
    // Process the fixed check counter.
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&syn_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->syn_fixed_check_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_SYN;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

            //bpf_printk("SYN %pI4 %llu %llu\n", &src_ip, timediff, config->syn_fixed_check_duration);

            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&syn_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->syn_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }
    /*
     1. Check rate limite detection
    */
    // Look up per-source state
    struct burst_state *state = bpf_map_lookup_elem(&burst_syn_state, &src_ip);
    if (!state) {
        // No existing state: initialize one
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(&burst_syn_state, &src_ip, &new_state, BPF_ANY);
    }
    else {
        // Calculate total bursts (including current burst if it already reached threshold) 
        __u32 total_bursts = state->burst_count;
        if (state->current_burst_count >= config->burst_pkt_threshold) {
            total_bursts++;
        }
        
        // If bursts per second threshold is reached, block source IP 
        if (total_bursts >= config->burst_count_threshold) {
            __u64 expire = now + global_config_val->black_ip_duration;
            __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (!blocked_time_p)
                bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
            else
                *blocked_time_p = expire;

            //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_TCP_SYN_ATTACK_BURST_BLOCK;
            // Send the event to user space on the current CPU.
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            return XDP_DROP;
        }

        // Update state for each SYN packet 
        if (now - state->last_reset >= ONE_SECOND_NS) { 
            // Reset state for the new second
            state->last_reset = now;
            state->current_burst_count = 1;
            state->burst_count = 0;
            state->last_pkt_time = now;
        } else {
            // Within same one-second window 
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                // Gap too long: the previous burst ends. 
                // Only count it if it met the threshold.
                if (state->current_burst_count >= config->burst_pkt_threshold) {
                    state->burst_count++;
                }
                // Start a new burst
                state->current_burst_count = 1;
            } else {
                // No gap: keep accumulating in current burst
                state->current_burst_count++;
            }
            state->last_pkt_time = now;
        }
        //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
    }

    /*
     2. Check syn challenge validation
    */

    // Check challenge state for this source IP.
    struct challenge_state *cstate = bpf_map_lookup_elem(&syn_challenge, &src_ip);
    if (cstate) {
        // If the state is too old, remove it.
        if (now - cstate->ts > config->challenge_timeout) {
            // We have to determine if it is retransmission TCP SYN
            if (cstate->seq != tcp->seq) {     
                bpf_map_delete_elem(&syn_challenge, &src_ip);
                cstate = NULL;
            }
        }
    }

    if (cstate == NULL) {
        // First SYN from this IP:
        struct challenge_state new_state = {0};
        new_state.stage = 1;
        new_state.ts = now;
        new_state.seq = tcp->seq;
        bpf_map_update_elem(&syn_challenge, &src_ip, &new_state, BPF_ANY);
        return XDP_DROP;

    } else if (cstate->stage == 1) {
        // Swap MAC addresses
        unsigned char tmp_mac[ETH_ALEN];
        __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

        // Swap IP addresses
        __be32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        // Swap TCP ports
        __be16 tmp_port = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = tmp_port;

        // Set SYN-ACK flags with wrong check sum to get new syn if client is correct one.
        tcp->ack = 1;
        tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
        tcp->seq = bpf_htonl(bpf_get_prandom_u32());
        tcp->check = 0;
        ip->check = iph_csum(ip);

        // Update challenge state.
        cstate->stage = 2;
        cstate->ts = now;

        return XDP_TX;
    }
    else if (cstate->stage == 2) {
        // This is the client's follow-up SYN in response to our challenge.
        // Remove the challenge state and allow the packet to be processed normally.
        bpf_map_delete_elem(&syn_challenge, &src_ip);
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&syn_counter_fixed, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->syn_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&syn_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->syn_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[SYN] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_TCP_SYN_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
        
        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_SYN;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
        return XDP_DROP;
    }

    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}


/*---------------------------------------------- XDP ACK Defense ------------------------------------------*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_ack_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} ack_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} ack_counter_fixed_metrics SEC(".maps");


/* Map for per-source state: key: source IP (in network byte order), value: burst_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_ack_state SEC(".maps");

SEC("xdp")
int xdp_parse_ack(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header.
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;
    
    
    volatile struct global_config *global_config_val = &global_fw_config.g_config;
    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    //__u32 dst_ip = ip->daddr;
    //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source));

    // Get current threshold from map
    __u32 key = 0;
    volatile struct ack_config *config = &global_fw_config.g_ack_config;

    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_ack_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;

    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&ack_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->ack_fixed_check_duration) {

            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_ACK;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&ack_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->ack_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    /*check limit detection if the source ip is not contained in tcp_established_map*/
    __u64 established_key = tcp->source;
    established_key = ((established_key << 32) | src_ip);
    __u8 * is_established = bpf_map_lookup_elem(&tcp_established_map, &established_key);
    if (is_established) {
        //bpf_printk("Established source IP %pI4: port is  = %d\n", &src_ip, tcp->source);
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    if (!is_established) {
        // Look up per-source state
        struct burst_state *state = bpf_map_lookup_elem(&burst_ack_state, &src_ip);
        if (!state) {
            // No existing state: initialize one
            struct burst_state new_state = {0};
            new_state.last_pkt_time = now;
            new_state.current_burst_count = 1;
            new_state.burst_count = 0;
            new_state.last_reset = now;
            bpf_map_update_elem(&burst_ack_state, &src_ip, &new_state, BPF_ANY);
        }
        else {
            // Calculate total bursts (including current burst if it already reached threshold) 
            __u32 total_bursts = state->burst_count;
            if (state->current_burst_count >= config->burst_pkt_threshold) {
                total_bursts++;
            }
            
            // If bursts per second threshold is reached, block source IP 
            if (total_bursts >= config->burst_count_threshold) {
                __u64 expire = now + global_config_val->black_ip_duration;
                __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
                if (!blocked_time_p)
                    bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
                else
                    *blocked_time_p = expire;
                //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

                struct event evt = {0};
                evt.time = now;
                evt.srcip = src_ip;
                evt.reason = EVENT_TCP_ACK_ATTACK_BURST_BLOCK;
                // Send the event to user space on the current CPU.
                bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

                return XDP_DROP;
            }

            // Update state for each ACK packet 
            if (now - state->last_reset >= ONE_SECOND_NS) { 
                // Reset state for the new second
                state->last_reset = now;
                state->current_burst_count = 1;
                state->burst_count = 0;
                state->last_pkt_time = now;
            } else {
                // Within same one-second window 
                if (now - state->last_pkt_time > config->burst_gap_ns) {
                    // Gap too long: the previous burst ends. 
                    // Only count it if it met the threshold.
                    if (state->current_burst_count >= config->burst_pkt_threshold) {
                        state->burst_count++;
                    }
                    // Start a new burst
                    state->current_burst_count = 1;
                } else {
                    // No gap: keep accumulating in current burst
                    state->current_burst_count++;
                }
                state->last_pkt_time = now;
            }
            //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
        }
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&ack_counter_fixed, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->ack_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&ack_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->ack_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[ACK] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_TCP_ACK_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_ACK;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

        return XDP_DROP;
    }
    
    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}


/*---------------------------------------------- XDP RST Defense ------------------------------------------*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_rst_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} rst_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} rst_counter_fixed_metrics SEC(".maps");

/* Map for per-source state: key: source IP (in network byte order), value: burst_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_rst_state SEC(".maps");

SEC("xdp")
int xdp_parse_rst(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header.
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    volatile struct global_config *global_config_val = &global_fw_config.g_config;

    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    //__u32 dst_ip = ip->daddr;
    //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

    // Get current threshold from map
    __u32 key = 0;

    volatile struct rst_config *config = &global_fw_config.g_rst_config;

    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_rst_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;
    
    // Process the fixed check counter.
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&rst_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {        
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->rst_fixed_check_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_RST;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&rst_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->rst_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }
    /*
     1. Check rate limite detection
    */
    // Look up per-source state
    struct burst_state *state = bpf_map_lookup_elem(&burst_rst_state, &src_ip);
    if (!state) {
        // No existing state: initialize one
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(&burst_rst_state, &src_ip, &new_state, BPF_ANY);
    }
    else {
        // Calculate total bursts (including current burst if it already reached threshold) 
        __u32 total_bursts = state->burst_count;
        if (state->current_burst_count >= config->burst_pkt_threshold) {
            total_bursts++;
        }
        
        // If bursts per second threshold is reached, block source IP 
        if (total_bursts >= config->burst_count_threshold) {
            __u64 expire = now + global_config_val->black_ip_duration;
            __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (!blocked_time_p)
                bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
            else
                *blocked_time_p = expire;
            //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_TCP_RST_ATTACK_BURST_BLOCK;
            // Send the event to user space on the current CPU.
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            return XDP_DROP;
        }

        // Update state for each RST packet 
        if (now - state->last_reset >= ONE_SECOND_NS) { 
            // Reset state for the new second
            state->last_reset = now;
            state->current_burst_count = 1;
            state->burst_count = 0;
            state->last_pkt_time = now;
        } else {
            // Within same one-second window 
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                // Gap too long: the previous burst ends. 
                // Only count it if it met the threshold.
                if (state->current_burst_count >= config->burst_pkt_threshold) {
                    state->burst_count++;
                }
                // Start a new burst
                state->current_burst_count = 1;
            } else {
                // No gap: keep accumulating in current burst
                state->current_burst_count++;
            }
            state->last_pkt_time = now;
        }
        //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&rst_counter_fixed, &src_ip);
    if (fixed_stats) {        
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->rst_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&rst_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->rst_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[RST] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_TCP_RST_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
        
        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_RST;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

        return XDP_DROP;
    }
    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}



/*---------------------------------------------- XDP ICMP Defense ------------------------------------------*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_icmp_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} icmp_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} icmp_counter_fixed_metrics SEC(".maps");

/* Map for per-source state: key: source IP (in network byte order), value: burst_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_icmp_state SEC(".maps");

SEC("xdp")
int xdp_parse_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Parse icmp header.
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct icmphdr) > data_end)
        return XDP_PASS;
    //struct icmphdr *icmp = (void *)ip + ihl;

    __u32 key = 0;

    volatile struct global_config *global_config_val = &global_fw_config.g_config;
    
    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    //__u32 dst_ip = ip->daddr;
    //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

    // Get current threshold from map
    key = 0;

    volatile struct icmp_config *config = &global_fw_config.g_icmp_config;

    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_icmp_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;
    
    // Process the fixed check counter.
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&icmp_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->icmp_fixed_check_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_ICMP;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&icmp_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->icmp_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    /*
     1. Check rate limite detection
    */
    // Look up per-source state
    struct burst_state *state = bpf_map_lookup_elem(&burst_icmp_state, &src_ip);
    if (!state) {
        // No existing state: initialize one
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(&burst_icmp_state, &src_ip, &new_state, BPF_ANY);
    }
    else {
        // Calculate total bursts (including current burst if it already reached threshold) 
        __u32 total_bursts = state->burst_count;
        if (state->current_burst_count >= config->burst_pkt_threshold) {
            total_bursts++;
        }
        
        // If bursts per second threshold is reached, block source IP 
        if (total_bursts >= config->burst_count_threshold) {
            __u64 expire = now + global_config_val->black_ip_duration;
            __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (!blocked_time_p)
                bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
            else
                *blocked_time_p = expire;
            //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_ICMP_ATTACK_BURST_BLOCK;
            // Send the event to user space on the current CPU.
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            return XDP_DROP;
        }

        // Update state for each ICMP packet 
        if (now - state->last_reset >= ONE_SECOND_NS) { 
            // Reset state for the new second
            state->last_reset = now;
            state->current_burst_count = 1;
            state->burst_count = 0;
            state->last_pkt_time = now;
        } else {
            // Within same one-second window 
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                // Gap too long: the previous burst ends. 
                // Only count it if it met the threshold.
                if (state->current_burst_count >= config->burst_pkt_threshold) {
                    state->burst_count++;
                }
                // Start a new burst
                state->current_burst_count = 1;
            } else {
                // No gap: keep accumulating in current burst
                state->current_burst_count++;
            }
            state->last_pkt_time = now;
        }
        //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&icmp_counter_fixed, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->icmp_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&icmp_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->icmp_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[ICMP] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_ICMP_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);
        
        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_ICMP;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

        return XDP_DROP;
    }
    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}


/*---------------------------------------------- XDP UDP Defense ------------------------------------------*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_udp_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} udp_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct flood_stats);
} udp_counter_fixed_metrics SEC(".maps");

/* Map for per-source state: key: source IP (in network byte order), value: burst_state */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_udp_state SEC(".maps");

SEC("xdp")
int xdp_parse_udp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP header.
    
    
    int ihl = ip->ihl * 4;
    if ((void *)ip + ihl + sizeof(struct udphdr) > data_end)
        return XDP_PASS;
    //struct udphdr *udp = (void *)ip + ihl;
    
    __u32 key = 0;
    volatile struct global_config *global_config_val = &global_fw_config.g_config;
    
    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    //__u32 dst_ip = ip->daddr;
    //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

    // Get current threshold from map
    key = 0;
    volatile struct udp_config *config = &global_fw_config.g_udp_config;

    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_udp_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;
    
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&udp_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->udp_fixed_check_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_UDP;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);

            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&udp_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->udp_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }
    /*
     1. Check rate limite detection
    */
    // Look up per-source state
    struct burst_state *state = bpf_map_lookup_elem(&burst_udp_state, &src_ip);
    if (!state) {
        // No existing state: initialize one
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(&burst_udp_state, &src_ip, &new_state, BPF_ANY);
    }
    else {
        // Calculate total bursts (including current burst if it already reached threshold) 
        __u32 total_bursts = state->burst_count;
        if (state->current_burst_count >= config->burst_pkt_threshold) {
            total_bursts++;
        }
        
        // If bursts per second threshold is reached, block source IP 
        if (total_bursts >= config->burst_count_threshold) {
            __u64 expire = now + global_config_val->black_ip_duration;
            __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (!blocked_time_p)
                bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
            else
                *blocked_time_p = expire;
            //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_UDP_ATTACK_BURST_BLOCK;
            // Send the event to user space on the current CPU.
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            return XDP_DROP;
        }

        // Update state for each UDP packet 
        if (now - state->last_reset >= ONE_SECOND_NS) { 
            // Reset state for the new second
            state->last_reset = now;
            state->current_burst_count = 1;
            state->burst_count = 0;
            state->last_pkt_time = now;
        } else {
            // Within same one-second window 
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                // Gap too long: the previous burst ends. 
                // Only count it if it met the threshold.
                if (state->current_burst_count >= config->burst_pkt_threshold) {
                    state->burst_count++;
                }
                // Start a new burst
                state->current_burst_count = 1;
            } else {
                // No gap: keep accumulating in current burst
                state->current_burst_count++;
            }
            state->last_pkt_time = now;
        }
        //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&udp_counter_fixed, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->udp_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&udp_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->udp_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[UDP] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_UDP_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_UDP;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
        
        return XDP_DROP;
    }
    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}

/*---------------------------------------------- XDP GRE Defense ------------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} global_gre_pkt_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct flood_stats);
} gre_counter_fixed SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct flood_stats);
} gre_counter_fixed_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, struct burst_state);
} burst_gre_state SEC(".maps");

SEC("xdp")
int xdp_parse_gre(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_GRE)
        return XDP_PASS;

    __u32 key = 0;

    volatile struct global_config *global_config_val = &global_fw_config.g_config;

    __u32 src_ip = ip->saddr;

    // Get current threshold from map
    key = 0;
    volatile struct gre_config *config = &global_fw_config.g_gre_config;

    __u64 *pkt_cnt = bpf_map_lookup_elem(&global_gre_pkt_counter, &key);
    if (!pkt_cnt) return XDP_PASS;
    
    // Process the fixed check counter.
    struct flood_stats *fixed_stats = bpf_map_lookup_elem(&gre_counter_fixed_metrics, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->gre_fixed_check_duration) {
            struct fixed_ip_event fixed_evt = {0};
            fixed_evt.srcip = src_ip;
            fixed_evt.fixed_type = FIXED_IP_RING_BUF_GRE;
            fixed_evt.duration = timediff;
            fixed_evt.pkt_count = fixed_stats->count;
            fixed_evt.over_fixed = 0;
            bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&gre_counter_fixed_metrics, &src_ip, &new_stats, BPF_ANY);
    }

    volatile struct global_attack_stats * global_attack_stats_ptr = &global_fw_config.g_attack_stats;
    if (global_attack_stats_ptr->gre_attack == 0) {
        __sync_fetch_and_add(pkt_cnt, 1);
        return XDP_PASS;
    }

    /*
     1. Check rate limite detection
    */
    // Look up per-source state
    struct burst_state *state = bpf_map_lookup_elem(&burst_gre_state, &src_ip);
    if (!state) {
        // No existing state: initialize one
        struct burst_state new_state = {0};
        new_state.last_pkt_time = now;
        new_state.current_burst_count = 1;
        new_state.burst_count = 0;
        new_state.last_reset = now;
        bpf_map_update_elem(&burst_gre_state, &src_ip, &new_state, BPF_ANY);
    }
    else {
        // Calculate total bursts (including current burst if it already reached threshold) 
        __u32 total_bursts = state->burst_count;
        if (state->current_burst_count >= config->burst_pkt_threshold) {
            total_bursts++;
        }
        
        // If bursts per second threshold is reached, block source IP 
        if (total_bursts >= config->burst_count_threshold) {
            __u64 expire = now + global_config_val->black_ip_duration;
            __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
            if (!blocked_time_p)
                bpf_map_update_elem(&blocked_ips, &src_ip, &expire, BPF_ANY);
            else
                *blocked_time_p = expire;
            //bpf_printk("Blocked source IP %pI4: bursts = %d\n", &src_ip, total_bursts);

            struct event evt = {0};
            evt.time = now;
            evt.srcip = src_ip;
            evt.reason = EVENT_GRE_ATTACK_BURST_BLOCK;
            // Send the event to user space on the current CPU.
            bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

            return XDP_DROP;
        }

        // Update state for each GRE packet 
        if (now - state->last_reset >= ONE_SECOND_NS) { 
            // Reset state for the new second
            state->last_reset = now;
            state->current_burst_count = 1;
            state->burst_count = 0;
            state->last_pkt_time = now;
        } else {
            // Within same one-second window 
            if (now - state->last_pkt_time > config->burst_gap_ns) {
                // Gap too long: the previous burst ends. 
                // Only count it if it met the threshold.
                if (state->current_burst_count >= config->burst_pkt_threshold) {
                    state->burst_count++;
                }
                // Start a new burst
                state->current_burst_count = 1;
            } else {
                // No gap: keep accumulating in current burst
                state->current_burst_count++;
            }
            state->last_pkt_time = now;
        }
        //bpf_printk("DEBUG: Burst current_burst_count %d (burst_count %d)\n", state->current_burst_count, state->burst_count);
    }

    // Process the fixed check counter.
    fixed_stats = bpf_map_lookup_elem(&gre_counter_fixed, &src_ip);
    if (fixed_stats) {
        __u64 timediff = now - fixed_stats->last_ts;
        if (timediff > config->gre_fixed_check_duration) {
            fixed_stats->count = 1;
            fixed_stats->last_ts = now;
        } else {
            fixed_stats->count += 1;
        }

    } else {
        struct flood_stats new_stats = {0};
        new_stats.detected = 0;
        new_stats.count = 1;
        new_stats.last_ts = now;
        bpf_map_update_elem(&gre_counter_fixed, &src_ip, &new_stats, BPF_ANY);
    }

    // Check if either threshold is exceeded.

    if (fixed_stats && fixed_stats->count > config->gre_fixed_threshold) {
        __u64 block_exp = now + global_config_val->black_ip_duration;
        __u64 *blocked_time_p = bpf_map_lookup_elem(&blocked_ips, &src_ip);
        if (!blocked_time_p)
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
        else
            *blocked_time_p = block_exp;
        //bpf_printk("[GRE] IP %pI4 blocked for 15-second threshold\n", &src_ip);

        struct event evt = {0};
        evt.time = now;
        evt.srcip = src_ip;
        evt.reason = EVENT_GRE_ATTACK_FIXED_BLOCK;
        // Send the event to user space on the current CPU.
        bpf_ringbuf_output(&ring_buf_events, &evt, sizeof(evt), 0);

        struct fixed_ip_event fixed_evt = {0};
        fixed_evt.srcip = src_ip;
        fixed_evt.fixed_type = FIXED_IP_RING_BUF_GRE;
        fixed_evt.duration = (now - fixed_stats->last_ts);
        fixed_evt.pkt_count = fixed_stats->count;
        fixed_evt.over_fixed = 1;
        bpf_ringbuf_output(&fixed_ip_ring_buf_events, &fixed_evt, sizeof(fixed_evt), 0);
        
        return XDP_DROP;
    }
    __sync_fetch_and_add(pkt_cnt, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";