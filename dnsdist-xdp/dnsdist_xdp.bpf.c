#include "vmlinux_local.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/errno.h>

#include "bpf/compiler.h"

#include "dnsdist_xdp.h"

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define ETH_ALEN 6

/* Set this to 1 to enable XSK support, 0 to disable */
#define USE_XSK 1  // Change to 0 to disable XSK support

#if USE_XSK
#define UseXsk
#endif

struct cursor {
    void *pos;
    void *end;
};

struct vlanhdr {
    __be16 tci;
    __be16 encap_proto;
};

static inline void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
    c->end = (void *)(long)ctx->data_end;
    c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)                            \
static inline struct STRUCT *parse_ ## STRUCT (struct cursor *c)  \
{                                                                 \
    struct STRUCT *ret = c->pos;                                  \
    if (c->pos + sizeof(struct STRUCT) > c->end)                  \
        return 0;                                                 \
    c->pos += sizeof(struct STRUCT);                              \
    return ret;                                                   \
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

static inline struct ethhdr *parse_eth(struct cursor *c, __be16 *eth_proto)
{
    struct ethhdr *eth;

    if (!(eth = parse_ethhdr(c)))
        return 0;

    *eth_proto = eth->h_proto;
    if (*eth_proto == bpf_htons(ETH_P_8021Q) ||
        *eth_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlanhdr *vlan;

        if (!(vlan = parse_vlanhdr(c)))
            return 0;

        *eth_proto = vlan->encap_proto;
        if (*eth_proto == bpf_htons(ETH_P_8021Q) ||
            *eth_proto == bpf_htons(ETH_P_8021AD)) {
            if (!(vlan = parse_vlanhdr(c)))
                return 0;

            *eth_proto = vlan->encap_proto;
        }
    }
    return eth;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, __u32);
    __type(value, struct map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} v4filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct in6_addr);
    __type(value, struct map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} v6filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct dns_qname);
    __type(value, struct map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} qnamefilter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct CIDR4);
    __type(value, struct map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr4filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct CIDR6);
    __type(value, struct map_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr6filter SEC(".maps");

#ifdef UseXsk
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, DDIST_MAX_NUMBER_OF_QUEUES);
    __type(key, __u32);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct IPv4AndPort);
    __type(value, bool);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xskDestinationsV4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DDIST_MAPS_SIZE);
    __type(key, struct IPv6AndPort);
    __type(value, bool);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xskDestinationsV6 SEC(".maps");
#endif


static inline void update_checksum(__u16 *csum, __u16 old_val, __u16 new_val)
{
    __u32 new_csum_value;
    __u32 new_csum_comp;
    __u32 undo;

    undo = ~((__u32)*csum) + ~((__u32)old_val);
    new_csum_value = undo + (undo < ~((__u32)old_val)) + (__u32)new_val;
    new_csum_comp = new_csum_value + (new_csum_value < ((__u32)new_val));
    new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
    new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
    *csum = (__u16)~new_csum_comp;
}

static inline void set_tc_bit(struct udphdr* udp, struct dnshdr* dns)
{
    __u16 old_val = dns->flags.as_value;

    dns->flags.as_bits_and_pieces.ad = 0;
    dns->flags.as_bits_and_pieces.qr = 1;
    dns->flags.as_bits_and_pieces.tc = 1;

    __u16 tmp = udp->dest;
    udp->dest = udp->source;
    udp->source = tmp;

    update_checksum(&udp->check, old_val, dns->flags.as_value);
}

static inline struct map_value* check_qname(struct cursor* c)
{
    struct dns_qname qkey = {0};
    __u8 qname_byte;
    __u16 qtype;
    int length = 0;

    for (int i = 0; i < 255; i++) {
        if (bpf_probe_read_kernel(&qname_byte, sizeof(qname_byte), c->pos))
            return NULL;
        c->pos += 1;
        if (length == 0) {
            if (qname_byte == 0 || qname_byte > 63) {
                break;
            }
            length += qname_byte;
        }
        else {
            length--;
        }
        if (qname_byte >= 'A' && qname_byte <= 'Z') {
            qkey.qname[i] = qname_byte + ('a' - 'A');
        }
        else {
            qkey.qname[i] = qname_byte;
        }
    }

    if (qname_byte != 0) {
        return NULL;
    }

    if (bpf_probe_read_kernel(&qtype, sizeof(qtype), c->pos))
        return NULL;

    struct map_value* value;

    qkey.qtype = bpf_htons(qtype);
    value = bpf_map_lookup_elem(&qnamefilter, &qkey);
    if (value) {
        return value;
    }

    qkey.qtype = 65535;
    return bpf_map_lookup_elem(&qnamefilter, &qkey);
}

static inline enum xdp_action parseIPV4(struct xdp_md* ctx, struct cursor* c)
{
    struct iphdr* ipv4;
    struct udphdr* udp = NULL;
    struct dnshdr* dns = NULL;
    if (!(ipv4 = parse_iphdr(c))) {
        return XDP_PASS;
    }
    switch (ipv4->protocol) {
    case IPPROTO_UDP: {
        if (!(udp = parse_udphdr(c))) {
            return XDP_PASS;
        }
#ifdef UseXsk
        struct IPv4AndPort v4Dest = {0};
        v4Dest.port = udp->dest;
        v4Dest.addr = ipv4->daddr;
        if (!bpf_map_lookup_elem(&xskDestinationsV4, &v4Dest)) {
            return XDP_PASS;
        }
#else
        if (!IN_DNS_PORT_SET(udp->dest)) {
            return XDP_PASS;
        }
#endif
        if (!(dns = parse_dnshdr(c))) {
            return XDP_DROP;
        }
        break;
    }
#ifdef UseXsk
    case IPPROTO_TCP: {
        return XDP_PASS;
    }
#endif
    default:
        return XDP_PASS;
    }

    struct CIDR4 key;
    key.addr = bpf_htonl(ipv4->saddr);

    struct map_value* value = bpf_map_lookup_elem(&v4filter, &key.addr);
    if (value) {
        goto res;
    }

    key.cidr = 32;
    key.addr = bpf_htonl(key.addr);
    value = bpf_map_lookup_elem(&cidr4filter, &key);
    if (value) {
        goto res;
    }

    const __u16 fragMask = bpf_htons(~(1 << 14));
    __u16 frag = ipv4->frag_off & fragMask;
    if (frag != 0) {
        return XDP_PASS;
    }

    if (dns) {
        value = check_qname(c);
    }
    if (value) {
    res:
        __sync_fetch_and_add(&value->counter, 1);
        if (value->action == DNS_TC && udp && dns) {
            set_tc_bit(udp, dns);
            __u32 swap_ipv4 = ipv4->daddr;
            ipv4->daddr = ipv4->saddr;
            ipv4->saddr = swap_ipv4;
            return XDP_TX;
        }

        if (value->action == DNS_DROP) {
            return XDP_DROP;
        }
    }

    return XDP_REDIRECT;
}

static inline enum xdp_action parseIPV6(struct xdp_md* ctx, struct cursor* c)
{
    struct ipv6hdr* ipv6;
    struct udphdr* udp = NULL;
    struct dnshdr* dns = NULL;
    if (!(ipv6 = parse_ipv6hdr(c))) {
        return XDP_PASS;
    }
    switch (ipv6->nexthdr) {
    case IPPROTO_UDP: {
        if (!(udp = parse_udphdr(c))) {
            return XDP_PASS;
        }
#ifdef UseXsk
        struct IPv6AndPort v6Dest = {0};
        v6Dest.port = udp->dest;
        __builtin_memcpy(&v6Dest.addr, &ipv6->daddr, sizeof(v6Dest.addr));
        if (!bpf_map_lookup_elem(&xskDestinationsV6, &v6Dest)) {
            return XDP_PASS;
        }
#else
        if (!IN_DNS_PORT_SET(udp->dest)) {
            return XDP_PASS;
        }
#endif
        if (!(dns = parse_dnshdr(c))) {
            return XDP_DROP;
        }
        break;
    }
#ifdef UseXsk
    case IPPROTO_TCP: {
        return XDP_PASS;
    }
#endif
    default:
        return XDP_PASS;
    }

    struct CIDR6 key;
    __builtin_memcpy(&key.addr, &ipv6->saddr, sizeof(key.addr));

    struct map_value* value = bpf_map_lookup_elem(&v6filter, &key.addr);
    if (value) {
        goto res;
    }

    key.cidr = 128;
    value = bpf_map_lookup_elem(&cidr6filter, &key);
    if (value) {
        goto res;
    }

    if (dns) {
        value = check_qname(c);
    }
    if (value) {
    res:
        __sync_fetch_and_add(&value->counter, 1);
        if (value->action == DNS_TC && udp && dns) {
            set_tc_bit(udp, dns);
            struct in6_addr swap_ipv6;
            __builtin_memcpy(&swap_ipv6, &ipv6->daddr, sizeof(swap_ipv6));
            __builtin_memcpy(&ipv6->daddr, &ipv6->saddr, sizeof(ipv6->daddr));
            __builtin_memcpy(&ipv6->saddr, &swap_ipv6, sizeof(ipv6->saddr));
            return XDP_TX;
        }
        if (value->action == DNS_DROP) {
            return XDP_DROP;
        }
    }
    return XDP_REDIRECT;
}

SEC("xdp")
int xdp_dns_filter(struct xdp_md* ctx)
{
    struct cursor c;
    struct ethhdr* eth;
    __u16 eth_proto;
    enum xdp_action r;

    cursor_init(&c, ctx);

    if ((eth = parse_eth(&c, &eth_proto))) {
        if (eth_proto == bpf_htons(ETH_P_IP)) {
            r = parseIPV4(ctx, &c);
            goto res;
        }
        else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
            r = parseIPV6(ctx, &c);
            goto res;
        }
        return XDP_PASS;
    }
    return XDP_PASS;
res:
    switch (r) {
    case XDP_REDIRECT:
#ifdef UseXsk
        return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
#else
        return XDP_PASS;
#endif
    case XDP_TX: {
        __u8 swap_eth[ETH_ALEN];
        __builtin_memcpy(swap_eth, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, swap_eth, ETH_ALEN);
        return XDP_TX;
    }
    default:
        return r;
    }
}

char _license[] SEC("license") = "GPL";
