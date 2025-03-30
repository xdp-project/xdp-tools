#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int udp_ddos(struct xdp_md *ctx) {
    // Your UDP DDoS mitigation logic here
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check packet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return XDP_DROP; // Example: Drop all UDP packets
}

char _license[] SEC("license") = "GPL";
