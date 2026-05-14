#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define MAX_PACKETS 5

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} n_packets_by_ip SEC(".maps");

SEC("xdp")
int xdp_filter_tcp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int dst_ip = ip->daddr;

    if (!tcp->syn && !tcp->ack)
        return XDP_PASS;

    if (tcp->syn)
        bpf_printk("got syn tcp packet from %d\n", dst_ip);
    else
        bpf_printk("got ack tcp packet from %d\n", dst_ip);

    u8 *n_packets = bpf_map_lookup_elem(&n_packets_by_ip, &dst_ip);
    if (!n_packets) {
        if (tcp->ack)
            return XDP_PASS;
        int val = 1;
        bpf_map_update_elem(&n_packets_by_ip, &dst_ip, &val, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->ack) {
        if (*n_packets > 0) {
            (*n_packets)--;
        }
        return XDP_PASS;
    }

    (*n_packets)++;
    if (*n_packets > MAX_PACKETS) {
        bpf_printk("dropped with n_packets=%d\n", *n_packets);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";