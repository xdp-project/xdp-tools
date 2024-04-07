/*
   SipHash reference C implementation

   Copyright (c) 2012-2016 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x, b) (__u64)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (__u8)((v));                                                   \
    (p)[1] = (__u8)((v) >> 8);                                              \
    (p)[2] = (__u8)((v) >> 16);                                             \
    (p)[3] = (__u8)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (__u32)((v)));                                           \
    U32TO8_LE((p) + 4, (__u32)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((__u64)((p)[0])) | ((__u64)((p)[1]) << 8) |                        \
     ((__u64)((p)[2]) << 16) | ((__u64)((p)[3]) << 24) |                 \
     ((__u64)((p)[4]) << 32) | ((__u64)((p)[5]) << 40) |                 \
     ((__u64)((p)[6]) << 48) | ((__u64)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

#ifdef DEBUG
#define TRACE                                                           \
        bpf_printk("v0 %x %x\n", (v0 >> 32), (__u32)v0); \
        bpf_printk("v1 %x %x\n", (v1 >> 32), (__u32)v1); \
        bpf_printk("v2 %x %x\n", (v2 >> 32), (__u32)v2); \
        bpf_printk("v3 %x %x\n", (v3 >> 32), (__u32)v3);
#else
#define TRACE
#endif

#define STRINGIFY_HELPER(A) #A
#define STRINGIFY(...) STRINGIFY_HELPER(__VA_ARGS__)
#define COOKIE_SECRET_STR ((const char *)STRINGIFY(COOKIE_SECRET))

#define HEXTONIBBLE(c) (*(c) >= 'A' ? (*(c) - 'A')+10 : (*(c)-'0'))
#define HEXTOBYTE(c) (HEXTONIBBLE(c)*16 + HEXTONIBBLE(c+1))

#define COOKIE_SECRET_K0 \
    ( ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+ 0) <<  0) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+ 2) <<  8) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+ 4) << 16) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+ 6) << 24) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+ 8) << 32) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+10) << 40) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+12) << 48) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+14) << 56))

#define COOKIE_SECRET_K1 \
    ( ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+16) <<  0) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+18) <<  8) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+20) << 16) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+22) << 24) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+24) << 32) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+26) << 40) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+28) << 48) \
    | ((__u64)HEXTOBYTE(COOKIE_SECRET_STR+30) << 56))

#define INLENv4 20
#define INLENv6 32
#define OUTLEN   8
static inline void siphash_ipv4(const __u8 *in, __u8 *out)
{
    __u64 v0 = 0x736f6d6570736575ULL ^ COOKIE_SECRET_K0;
    __u64 v1 = 0x646f72616e646f6dULL ^ COOKIE_SECRET_K1;
    __u64 v2 = 0x6c7967656e657261ULL ^ COOKIE_SECRET_K0;
    __u64 v3 = 0x7465646279746573ULL ^ COOKIE_SECRET_K1;
    __u64 m;
    int i;
    const __u8 *end = in + INLENv4 - (INLENv4 % sizeof(__u64));
    const int left = INLENv4 & 7;
    __u64 b = ((__u64)INLENv4) << 56;
    if (OUTLEN == 16)
        v1 ^= 0xee;

    for (; in != end; in += 8) {
        m = U8TO64_LE(in);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((__u64)in[6]) << 48;
    case 6:
        b |= ((__u64)in[5]) << 40;
    case 5:
        b |= ((__u64)in[4]) << 32;
    case 4:
        b |= ((__u64)in[3]) << 24;
    case 3:
        b |= ((__u64)in[2]) << 16;
    case 2:
        b |= ((__u64)in[1]) << 8;
    case 1:
        b |= ((__u64)in[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (OUTLEN == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);
}

static inline void siphash_ipv6(const __u8 *in, __u8 *out)
{
    __u64 v0 = 0x736f6d6570736575ULL ^ COOKIE_SECRET_K0;
    __u64 v1 = 0x646f72616e646f6dULL ^ COOKIE_SECRET_K1;
    __u64 v2 = 0x6c7967656e657261ULL ^ COOKIE_SECRET_K0;
    __u64 v3 = 0x7465646279746573ULL ^ COOKIE_SECRET_K1;
    __u64 m;
    int i;
    const __u8 *end = in + INLENv6 - (INLENv6 % sizeof(__u64));
    const int left = INLENv6 & 7;
    __u64 b = ((__u64)INLENv6) << 56;
    if (OUTLEN == 16)
        v1 ^= 0xee;

    for (; in != end; in += 8) {
        m = U8TO64_LE(in);
        v3 ^= m;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }

    switch (left) {
    case 7:
        b |= ((__u64)in[6]) << 48;
    case 6:
        b |= ((__u64)in[5]) << 40;
    case 5:
        b |= ((__u64)in[4]) << 32;
    case 4:
        b |= ((__u64)in[3]) << 24;
    case 3:
        b |= ((__u64)in[2]) << 16;
    case 2:
        b |= ((__u64)in[1]) << 8;
    case 1:
        b |= ((__u64)in[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (OUTLEN == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);
}
