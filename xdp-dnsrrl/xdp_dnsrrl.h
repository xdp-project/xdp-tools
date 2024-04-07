#define COOKIE_SECRET 00112233445566778899AABBCCDDEEFF
/* The secret with which to verify the validity of DNS Cookies.
 * Requests with valid DNS Cookies will not be ratelimited.
 */

#define RRL_N_CPUS            2
/* This should be the number of CPUs on your system. Get it by running:
 *
 *      echo "CPUs: $(grep -c processor /proc/cpuinfo)"
 */

#define RRL_SIZE        1000000
/* This option gives the size of the hashtable. More buckets
 * use more memory, and reduce the chance of hash collisions.
 */

#define RRL_RATELIMIT       200
/* The max qps allowed (from one query source). If set to 0 then it is disabled
 * (unlimited rate). Once the rate limit is reached, responses will be dropped.
 * However, one in every RRL_SLIP number of responses is allowed, with the TC
 * bit set. If slip is set to 2, the outgoing response rate will be halved. If
 * it's set to 3, the outgoing response rate will be one-third, and so on.  If
 * you set RRL_SLIP to 10, traffic is reduced to 1/10th.
 */

#define RRL_IPv4_PREFIX_LEN  24
/* IPv4 prefix length. Addresses are grouped by netblock.
 */

#define RRL_IPv6_PREFIX_LEN  48
/* IPv6 prefix length. Addresses are grouped by netblock.
 */

#define RRL_SLIP              2
/* This option controls the number of packets discarded before we send back a
 * SLIP response (a response with "truncated" bit set to one). 0 disables the
 * sending of SLIP packets, 1 means every query will get a SLIP response.
 * Default is 2, cuts traffic in half and legit users have a fair chance to get
 * a +TC response.
 */

#define RRL_MASK_CONCAT1(X)  RRL_MASK ## X
#define RRL_MASK_CONCAT2(X)  RRL_MASK_CONCAT1(X)
#define RRL_IPv4_MASK        RRL_MASK_CONCAT2(RRL_IPv4_PREFIX_LEN)
#define RRL_IPv6_MASK        RRL_MASK_CONCAT2(RRL_IPv6_PREFIX_LEN)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define RRL_MASK1            0x00000080
#define RRL_MASK2            0x000000C0
#define RRL_MASK3            0x000000E0
#define RRL_MASK4            0x000000F0
#define RRL_MASK5            0x000000F8
#define RRL_MASK6            0x000000FC
#define RRL_MASK7            0x000000FE
#define RRL_MASK8            0x000000FF
#define RRL_MASK9            0x000080FF
#define RRL_MASK10           0x0000C0FF
#define RRL_MASK11           0x0000E0FF
#define RRL_MASK12           0x0000F0FF
#define RRL_MASK13           0x0000F8FF
#define RRL_MASK14           0x0000FCFF
#define RRL_MASK15           0x0000FEFF
#define RRL_MASK16           0x0000FFFF
#define RRL_MASK17           0x0080FFFF
#define RRL_MASK18           0x00C0FFFF
#define RRL_MASK19           0x00E0FFFF
#define RRL_MASK20           0x00F0FFFF
#define RRL_MASK21           0x00F8FFFF
#define RRL_MASK22           0x00FCFFFF
#define RRL_MASK23           0x00FEFFFF
#define RRL_MASK24           0x00FFFFFF
#define RRL_MASK25           0x80FFFFFF
#define RRL_MASK26           0xC0FFFFFF
#define RRL_MASK27           0xE0FFFFFF
#define RRL_MASK28           0xF0FFFFFF
#define RRL_MASK29           0xF8FFFFFF
#define RRL_MASK30           0xFCFFFFFF
#define RRL_MASK31           0xFEFFFFFF
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define RRL_MASK1            0x80000000
#define RRL_MASK2            0xC0000000
#define RRL_MASK3            0xE0000000
#define RRL_MASK4            0xF0000000
#define RRL_MASK5            0xF8000000
#define RRL_MASK6            0xFC000000
#define RRL_MASK7            0xFE000000
#define RRL_MASK8            0xFF000000
#define RRL_MASK9            0xFF800000
#define RRL_MASK10           0xFFC00000
#define RRL_MASK11           0xFFE00000
#define RRL_MASK12           0xFFF00000
#define RRL_MASK13           0xFFF80000
#define RRL_MASK14           0xFFFC0000
#define RRL_MASK15           0xFFFE0000
#define RRL_MASK16           0xFFFF0000
#define RRL_MASK17           0xFFFF8000
#define RRL_MASK18           0xFFFFC000
#define RRL_MASK19           0xFFFFE000
#define RRL_MASK20           0xFFFFF000
#define RRL_MASK21           0xFFFFF800
#define RRL_MASK22           0xFFFFFC00
#define RRL_MASK23           0xFFFFFE00
#define RRL_MASK24           0xFFFFFF00
#define RRL_MASK25           0xFFFFFF80
#define RRL_MASK26           0xFFFFFFC0
#define RRL_MASK27           0xFFFFFFE0
#define RRL_MASK28           0xFFFFFFF0
#define RRL_MASK29           0xFFFFFFF8
#define RRL_MASK30           0xFFFFFFFC
#define RRL_MASK31           0xFFFFFFFE
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#define RRL_MASK33           RRL_MASK1
#define RRL_MASK34           RRL_MASK2
#define RRL_MASK35           RRL_MASK3
#define RRL_MASK36           RRL_MASK4
#define RRL_MASK37           RRL_MASK5
#define RRL_MASK38           RRL_MASK6
#define RRL_MASK39           RRL_MASK7
#define RRL_MASK40           RRL_MASK8
#define RRL_MASK41           RRL_MASK9
#define RRL_MASK42           RRL_MASK10
#define RRL_MASK43           RRL_MASK11
#define RRL_MASK44           RRL_MASK12
#define RRL_MASK45           RRL_MASK13
#define RRL_MASK46           RRL_MASK14
#define RRL_MASK47           RRL_MASK15
#define RRL_MASK48           RRL_MASK16
#define RRL_MASK49           RRL_MASK17
#define RRL_MASK50           RRL_MASK18
#define RRL_MASK51           RRL_MASK19
#define RRL_MASK52           RRL_MASK20
#define RRL_MASK53           RRL_MASK21
#define RRL_MASK54           RRL_MASK22
#define RRL_MASK55           RRL_MASK23
#define RRL_MASK56           RRL_MASK24
#define RRL_MASK57           RRL_MASK25
#define RRL_MASK58           RRL_MASK26
#define RRL_MASK59           RRL_MASK27
#define RRL_MASK60           RRL_MASK28
#define RRL_MASK61           RRL_MASK29
#define RRL_MASK62           RRL_MASK30
#define RRL_MASK63           RRL_MASK31
#define RRL_MASK65           RRL_MASK1
#define RRL_MASK66           RRL_MASK2
#define RRL_MASK67           RRL_MASK3
#define RRL_MASK68           RRL_MASK4
#define RRL_MASK69           RRL_MASK5
#define RRL_MASK70           RRL_MASK6
#define RRL_MASK71           RRL_MASK7
#define RRL_MASK72           RRL_MASK8
#define RRL_MASK73           RRL_MASK9
#define RRL_MASK74           RRL_MASK10
#define RRL_MASK75           RRL_MASK11
#define RRL_MASK76           RRL_MASK12
#define RRL_MASK77           RRL_MASK13
#define RRL_MASK78           RRL_MASK14
#define RRL_MASK79           RRL_MASK15
#define RRL_MASK80           RRL_MASK16
#define RRL_MASK81           RRL_MASK17
#define RRL_MASK82           RRL_MASK18
#define RRL_MASK83           RRL_MASK19
#define RRL_MASK84           RRL_MASK20
#define RRL_MASK85           RRL_MASK21
#define RRL_MASK86           RRL_MASK22
#define RRL_MASK87           RRL_MASK23
#define RRL_MASK88           RRL_MASK24
#define RRL_MASK89           RRL_MASK25
#define RRL_MASK90           RRL_MASK26
#define RRL_MASK91           RRL_MASK27
#define RRL_MASK92           RRL_MASK28
#define RRL_MASK93           RRL_MASK29
#define RRL_MASK94           RRL_MASK30
#define RRL_MASK95           RRL_MASK31
#define RRL_MASK97           RRL_MASK1
#define RRL_MASK98           RRL_MASK2
#define RRL_MASK99           RRL_MASK3
#define RRL_MASK100          RRL_MASK4
#define RRL_MASK101          RRL_MASK5
#define RRL_MASK102          RRL_MASK6
#define RRL_MASK103          RRL_MASK7
#define RRL_MASK104          RRL_MASK8
#define RRL_MASK105          RRL_MASK9
#define RRL_MASK106          RRL_MASK10
#define RRL_MASK107          RRL_MASK11
#define RRL_MASK108          RRL_MASK12
#define RRL_MASK109          RRL_MASK13
#define RRL_MASK110          RRL_MASK14
#define RRL_MASK111          RRL_MASK15
#define RRL_MASK112          RRL_MASK16
#define RRL_MASK113          RRL_MASK17
#define RRL_MASK114          RRL_MASK18
#define RRL_MASK115          RRL_MASK19
#define RRL_MASK116          RRL_MASK20
#define RRL_MASK117          RRL_MASK21
#define RRL_MASK118          RRL_MASK22
#define RRL_MASK119          RRL_MASK23
#define RRL_MASK120          RRL_MASK24
#define RRL_MASK121          RRL_MASK25
#define RRL_MASK122          RRL_MASK26
#define RRL_MASK123          RRL_MASK27
#define RRL_MASK124          RRL_MASK28
#define RRL_MASK125          RRL_MASK29
#define RRL_MASK126          RRL_MASK30
#define RRL_MASK127          RRL_MASK31

#define DNS_PORT        53
#define RR_TYPE_OPT     41
#define OPT_CODE_COOKIE 10

#define THRESHOLD ((RRL_RATELIMIT) / (RRL_N_CPUS))
#define FRAME_SIZE   1000000000

/* tail call index */
#define DO_RATE_LIMIT_IPV6 0
#define DO_RATE_LIMIT_IPV4 1
#define COOKIE_VERIFY_IPv6 0
#define COOKIE_VERIFY_IPv4 1
#define SYN_COOKIE_VERIFY 0

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

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define NSEC_PER_SEC 1000000000L

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

#define NEXTHDR_TCP 6

#define TCPOPT_NOP 1
#define TCPOPT_EOL 0
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_TIMESTAMP 8

#define TCPOLEN_MSS 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10

#define TCP_TS_HZ 1000
#define TS_OPT_WSCALE_MASK 0xf
#define TS_OPT_SACK (1 << 4)
#define TS_OPT_ECN (1 << 5)
#define TSBITS 6
#define TSMASK (((__u32)1 << TSBITS) - 1)
#define TCP_MAX_WSCALE 14U

#define IPV4_MAXLEN 60
#define TCP_MAXLEN 60

#define DEFAULT_MSS4 1460
#define DEFAULT_MSS6 1440
#define DEFAULT_WSCALE 7
#define DEFAULT_TTL 64
#define MAX_ALLOWED_PORTS 8

#define swap(a, b) \
        do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define __get_unaligned_t(type, ptr) ({                                         \
        const struct { type x; } __attribute__((__packed__)) *__pptr = (typeof(__pptr))(ptr); \
        __pptr->x;                                                              \
})

#define get_unaligned(ptr) __get_unaligned_t(typeof(*(ptr)), (ptr))

