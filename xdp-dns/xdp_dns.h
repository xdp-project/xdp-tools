#define DNS_PORT        53
#define RR_TYPE_OPT     41

#define FRAME_SIZE   1000000000

/*
 *  Store the DNS header
 */
struct dnshdr {
        __u16 id;
        union {
                struct {
                        __u8  rd     : 1;
                        __u8  tc     : 1;
                        __u8  aa     : 1;
                        __u8  opcode : 4;
                        __u8  qr     : 1;

                        __u8  rcode  : 4;
                        __u8  cd     : 1;
                        __u8  ad     : 1;
                        __u8  z      : 1;
                        __u8  ra     : 1;
                }        as_bits_and_pieces;
                __u16 as_value;
        } flags;
        __u16 qdcount;
        __u16 ancount;
        __u16 nscount;
        __u16 arcount;
};

struct dns_qrr {
        __u16 qtype;
        __u16 qclass;
};

struct dns_rr {
        __u16 type;
        __u16 class;
        __u32 ttl;
        __u16 rdata_len;
} __attribute__((packed));

struct option {
        __u16 code;
        __u16 len;
        __u8  data[];
} __attribute__((packed));

/*
 *  Recalculate the checksum
 */
static __always_inline
void update_checksum(__u16 *csum, __u16 old_val, __u16 new_val)
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


//TCP

#define NSEC_PER_SEC 1000000000L

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

#define swap(a, b) \
        do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define __get_unaligned_t(type, ptr) ({                                         \
        const struct { type x; } __attribute__((__packed__)) *__pptr = (typeof(__pptr))(ptr); \
        __pptr->x;                                                              \
})

#define get_unaligned(ptr) __get_unaligned_t(typeof(*(ptr)), (ptr))

