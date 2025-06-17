#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define ETH_ALEN 6

#define DNS_PORT 53
#define DDIST_MAPS_SIZE 1024
#define DDIST_MAX_NUMBER_OF_QUEUES 64

#ifndef IN_DNS_PORT_SET
#define IN_DNS_PORT_SET(x) (x == bpf_htons(DNS_PORT))
#endif

struct dnshdr {
    __be16 id;
    union {
        struct {
            __u8 rd:1;
            __u8 tc:1;
            __u8 aa:1;
            __u8 opcode:4;
            __u8 qr:1;
            __u8 rcode:4;
            __u8 cd:1;
            __u8 ad:1;
            __u8 z:1;
            __u8 ra:1;
        } as_bits_and_pieces;
        __be16 as_value;
    } flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct dns_qname {
    __u8 qname[255];
    __be16 qtype;
};

enum dns_action {
    DNS_PASS = 0,
    DNS_DROP = 1,
    DNS_TC = 2
};

struct CIDR4 {
    __u32 cidr;
    __be32 addr;
};

struct CIDR6 {
    __u32 cidr;
    struct in6_addr addr;
};

struct IPv4AndPort {
    __be32 addr;
    __be16 port;
};

struct IPv6AndPort {
    struct in6_addr addr;
    __be16 port;
};

struct map_value {
    __u64 counter;
    enum dns_action action;
};

