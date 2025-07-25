//go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <linux/ipv6.h>
// #include <linux/in.h>

char __license[] SEC("license") = "GPL";

#define MAX_MAP_ENTRIES 16

// from: linux/if_ether.h (else we run into redefine-issues with vmlinux.h)
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
// from: linux/in.h
#define IPPROTO_TCP     6

struct tcp_data {
    __u16 sport;
    __u16 dport;
    __u16 window;
    __u16 mss;
    __u8  window_scale;
    __u8  options_len;
    __u8  options[16];
};

struct ip4_data {
    __u32 saddr;
    __u32 daddr;
    struct tcp_data tcp;
};

struct ip6_addr {
    __u32 addr[4];  // 64- and 128-bit handling is harder
};

struct ip6_data {
    struct ip6_addr saddr;
    struct ip6_addr daddr;
    struct tcp_data tcp;
};

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(value, sizeof(struct ip4_data));
} xdp_ip4_queue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(value, sizeof(struct ip6_data));
} xdp_ip6_queue SEC(".maps");

// L4 - TCP
static __always_inline int valid_l4_tcp(struct tcphdr *tcph, void *data_end) {
    // Ensure TCP header is within packet bounds
    if ((void *)(tcph + 1) > data_end) {
        return 0;
    }
    return 1;
}

static __always_inline void process_ip4_tcp(struct iphdr *ip4h, u32 ip4_hdr_len, struct ip4_data ip4d, void *data, void *data_end) {
    struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)ip4h + ip4_hdr_len);
    int ip4_tcp_hdr_len = sizeof(struct tcphdr);

    if (!valid_l4_tcp(tcph, data_end)) {
        return;
    }

    ip4d.tcp.sport = bpf_ntohs(tcph->source);
    ip4d.tcp.dport = bpf_ntohs(tcph->dest);
    ip4d.tcp.window = bpf_ntohs(tcph->window);

    const char log_ip4[] = "[eBPF] IP4-TCP: %pI4 => %pI4\n";
    bpf_trace_printk(log_ip4, sizeof(log_ip4), &ip4h->saddr, &ip4h->daddr);
}

static __always_inline void process_ip6_tcp(struct ipv6hdr *ip6h, u32 ip6_hdr_len, struct ip6_data ip6d, void *data, void *data_end) {
    const char log_ip6[] = "[eBPF] IP6-TCP: %pI6 => %pI6\n";
    bpf_trace_printk(log_ip6, sizeof(log_ip6), &ip6h->saddr, &ip6h->daddr);

    return;
    // todo: get correct ipv6hdr size
    /*
    int ip6_tcp_hdr_len = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

    struct tcphdr *tcph = (struct tcphdr *)((unsigned char *)ip6h + ip6_hdr_len);
    if (!valid_l4_tcp(ip4_hdr_len, tcph, data_end)) {
        return;
    }

    ip6d.tcp.sport = bpf_ntohs(tcph->source);
    ip6d.tcp.dport = bpf_ntohs(tcph->dest);
    ip6d.tcp.window = bpf_ntohs(tcph->window);
    */
}

// L3 - IP4 & IP6

static __always_inline void process_ip4(struct ethhdr *ethhdr, void *data, void *data_end) {
	struct iphdr *ip4h = (void *)(ethhdr + 1);
    int ip4_hdr_len = ip4h->ihl * 4;

    // bad IPv4
    if (ip4h + 1 > (struct iphdr *)data_end) {
        return;
    }
    if (ip4_hdr_len < sizeof(struct iphdr)) {
        return;
    }
    if ((void *)ip4h + ip4_hdr_len > data_end) {
        return;
    }
    // todo: check for fragmentation
    /*
    __u16 frag_off = bpf_ntohs(ip4h->frag_off);
    if (frag_off & (IP_MF | IP_OFFSET_MASK)) {
        if (frag_off & IP_OFFSET_MASK) {
            return;
        }
    }
    */

    // get src-ip
    struct ip4_data ip4d;
    ip4d.saddr = bpf_ntohl(ip4h->saddr);

    // debug log
    const char log_ip4[] = "[eBPF] IP4: %pI4 => %pI4 | Proto: %d\n";
    bpf_trace_printk(log_ip4, sizeof(log_ip4), &ip4h->saddr, &ip4h->daddr, ip4h->protocol);

    // proceed to TCP
    if (ip4h->protocol == IPPROTO_TCP) {
        ip4d.daddr = bpf_ntohl(ip4h->daddr);

        process_ip4_tcp(ip4h, ip4_hdr_len, ip4d, data, data_end);
    }
    return;
}

static __always_inline void process_ip6(struct ethhdr *ethhdr, void *data, void *data_end) {
    struct ipv6hdr *ip6h = (void *)(ethhdr + 1);
    // todo: IPv6 extensions not included in length..
    int ip6_hdr_len = sizeof(struct ipv6hdr);

    // bad IPv6
    if (ip6h + 1 > (struct ipv6hdr *)data_end) {
        return;
    }
    // todo: IPv6 extensions in length
    /*
    if (ip6_hdr_len < sizeof(struct ipv6hdr)) {
        return;
    }
    */
    // todo: fragmentation check

    // get src-ip
    struct ip6_data ip6d;
    __builtin_memcpy(&ip6d.saddr.addr, &ip6h->saddr, sizeof(ip6d.saddr.addr));
    ip6d.saddr.addr[0] = bpf_ntohl(ip6d.saddr.addr[0]);
    ip6d.saddr.addr[1] = bpf_ntohl(ip6d.saddr.addr[1]);
    ip6d.saddr.addr[2] = bpf_ntohl(ip6d.saddr.addr[2]);
    ip6d.saddr.addr[3] = bpf_ntohl(ip6d.saddr.addr[3]);
    __builtin_memcpy(&ip6d.daddr.addr, &ip6h->daddr, sizeof(ip6d.daddr.addr));
    ip6d.daddr.addr[0] = bpf_ntohl(ip6d.daddr.addr[0]);
    ip6d.daddr.addr[1] = bpf_ntohl(ip6d.daddr.addr[1]);
    ip6d.daddr.addr[2] = bpf_ntohl(ip6d.daddr.addr[2]);
    ip6d.daddr.addr[3] = bpf_ntohl(ip6d.daddr.addr[3]);

    // debug log
    const char log_ip6[] = "[eBPF] IP6: %pI6 => %pI6 | Proto: %d\n";
    bpf_trace_printk(log_ip6, sizeof(log_ip6), &ip6h->saddr, &ip6h->daddr, ip6h->nexthdr);
    /*
    const char log_ip6_p1[] = "[eBPF] IP6: Parts 1+2 (0x%x 0x%x)\n";
    bpf_trace_printk(log_ip6_p1, sizeof(log_ip6_p1), ip6d.saddr.addr[0], ip6d.saddr.addr[1]);
    const char log_ip6_p2[] = "[eBPF] IP6: Parts 3+4 (0x%x 0x%x)\n";
    bpf_trace_printk(log_ip6_p2, sizeof(log_ip6_p2), ip6d.saddr.addr[2], ip6d.saddr.addr[3]);
    */

    // proceed to TCP
    if (ip6h->nexthdr == IPPROTO_TCP) {
        process_ip6_tcp(ip6h, ip6_hdr_len, ip6d, data, data_end);
    }

    return;
}

// L2 - eth
static __always_inline int valid_l2_eth(struct ethhdr *ethhdr, void *data, void *data_end) {
    if ((void *)(ethhdr + 1) > data_end) {
        return 0;
    }
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    // NOTE: we have already limited processing to an interface; xdp currently does only capture inbound packets

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *ethhdr = data;

	if (!(valid_l2_eth(ethhdr, data, data_end))) {
        // L2 != ETH
        return XDP_PASS;
    }

    if (ethhdr->h_proto == bpf_htons(ETH_P_IP)) {
        process_ip4(ethhdr, data, data_end);

    } else if (ethhdr->h_proto == bpf_htons(ETH_P_IPV6)) {
        process_ip6(ethhdr, data, data_end);
    }
    // else: L3 != IP

done:
	return XDP_PASS;
}
