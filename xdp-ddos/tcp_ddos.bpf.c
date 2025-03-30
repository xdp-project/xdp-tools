#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int tcp_ddos(struct xdp_md *ctx) {
    // Your TCP DDoS mitigation logic here
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check packet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return XDP_DROP; // Example: Drop all TCP packets
}

char _license[] SEC("license") = "GPL";
