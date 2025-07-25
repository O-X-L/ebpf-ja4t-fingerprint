//go:build ignore

#include <vmlinux.h> // This should provide all kernel types and definitions
#include <bpf/bpf_helpers.h> // For BPF helper functions
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

#define MAX_MAP_ENTRIES 16

// from: /usr/include/linux/if_ether.h (else we run into redefine-issues with vmlinux.h)
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

static __always_inline void process_ip4(struct ethhdr *ethhdr, void *data_end) {
	struct iphdr *ip4 = (void *)(ethhdr + 1);
	if ((void *)(ip4 + 1) > data_end) {
		return;
	}

    u32 saddr = (__u32)(ip4->saddr);
    static const char fmt[] = "IP4: %d"; 
    bpf_trace_printk(fmt, sizeof(fmt), saddr);

    return;
}

static __always_inline void process_ip6(struct ethhdr *ethhdr, void *data_end) {
    struct ipv6hdr *ip6 = (void *)(ethhdr + 1);
    if ((void *)(ip6 + 1) > data_end) {
        // bad IPv6
        return;
    }

    // u128 saddr = (__u128)(ip6->saddr)

    static const char fmt[] = "IP6:"; 
    bpf_trace_printk(fmt, sizeof(fmt));

    return;
}

static __always_inline int parse_eth(struct ethhdr *ethhdr, void *data_end, u16 *eth_type) {
    u64 offset;

    offset = sizeof(*ethhdr);
    if ((void *)ethhdr + offset > data_end)
        return 0;
	*eth_type = ethhdr->h_proto;
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *ethhdr = data;
	u16 eth_type = 0;

	if (!(parse_eth(ethhdr, data_end, &eth_type))) {
        // L2 != ETH
        return XDP_PASS;
    }

    if (ethhdr->h_proto == bpf_htons(ETH_P_IP)) {
        process_ip4(ethhdr, data_end);
    } else if (ethhdr->h_proto == bpf_htons(ETH_P_IPV6)) {
        process_ip6(ethhdr, data_end);
    }
    // else: L3 != IP

done:
	return XDP_PASS;
}
