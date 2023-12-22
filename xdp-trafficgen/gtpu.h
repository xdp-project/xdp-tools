#include <linux/types.h>
#include <linux/unistd.h>

#define GTP_UDP_PORT 2152u

/* Version: GTPv1, Protocol Type: GTP, Others: 0 */
#define GTP_FLAGS 0x30

#define GTPU_ECHO_REQUEST (1)
#define GTPU_ECHO_RESPONSE (2)
#define GTPU_ERROR_INDICATION (26)
#define GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION (31)
#define GTPU_END_MARKER (254)
#define GTPU_G_PDU (255)

struct gtpuhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int pn : 1;
    unsigned int s : 1;
    unsigned int e : 1;
    unsigned int spare : 1;
    unsigned int pt : 1;
    unsigned int version : 3;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 3;
    unsigned int pt : 1;
    unsigned int spare : 1;
    unsigned int e : 1;
    unsigned int s : 1;
    unsigned int pn : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
    __u8 message_type;
    __u16 message_length;
    __u32 teid;
} __attribute__((packed));

struct gtpu_hdr_ext {
    __u16 sqn;
    __u8 npdu;
    __u8 next_ext;
} __attribute__((packed));

#define GTPU_EXT_TYPE_PDU_SESSION_CONTAINER (0x85)
#define PDU_SESSION_CONTAINER_PDU_TYPE_DL_PSU (0x00)
#define PDU_SESSION_CONTAINER_PDU_TYPE_UL_PSU (0x01)

struct gtp_pdu_session_container {
    __u8 length;
    __u8 spare1 : 4;
    __u8 pdu_type : 4;
    __u8 qfi    : 6;
    __u8 rqi    : 1;
    __u8 spare2 : 1;    
    __u8 next_ext;
} __attribute__((packed));