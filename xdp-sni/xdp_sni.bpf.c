/*
 * Copyright (c) 2024, BPFire.  All rights reserved.
 * Credit to Dylan Reimerink to work out extension for loop.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "vmlinux_local.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define SERVER_NAME_EXTENSION 0
#define MAX_DOMAIN_SIZE 127

struct domain_name {
    struct bpf_lpm_trie_key lpm_key;
    char server_name[MAX_DOMAIN_SIZE + 1];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct domain_name);
    __type(value, __u8);
    __uint(max_entries, 10000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sni_denylist SEC(".maps");


struct extension {
    __u16 type;
    __u16 len;
} __attribute__((packed));

struct sni_extension {
    __u16 list_len;
    __u8 type;
    __u16 len;
} __attribute__((packed));

static __always_inline void reverse_string(char *str, __u8 len) {
    for (int i = 0; i < (len - 1) / 2; i++) {
        char temp = str[i];
        str[i] = str[len - 1 - i];
        str[len - 1 - i] = temp;
    }
}

SEC("xdp")
int xdp_tls_sni(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    void *cursor = data;

    // Parse Ethernet header
    struct ethhdr *eth = cursor;
    if (cursor + sizeof(*eth) > data_end) goto end;
    cursor += sizeof(*eth);

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto end;

    // Parse IP header
    struct iphdr *ip = cursor;
    if (cursor + sizeof(*ip) > data_end) goto end;
    cursor += ip->ihl * 4; // IP header length in 32-bit words

    // Only process TCP traffic
    if (ip->protocol != IPPROTO_TCP) goto end;

    // Parse TCP header
    struct tcphdr *tcp = cursor;
    if (cursor + sizeof(*tcp) > data_end) goto end;
    cursor += tcp->doff * 4; // TCP header length in 32-bit words

    // Only process traffic on port 443 (HTTPS)
    if (tcp->dest != bpf_htons(443)) goto end;

    // Check if there's enough data for the TLS ClientHello
    if (data_end < cursor + 5) goto end;

    // TLS record header
    __u8 record_type = *((__u8 *)cursor);
    __u16 tls_version = bpf_ntohs(*(__u16 *)(cursor + 1));
    __u16 record_length = bpf_ntohs(*(__u16 *)(cursor + 3));

    if (record_type != 0x16 || tls_version < 0x0301) goto end; // Only handshake and TLSv1.0+
    cursor += 5;

    if (record_length > 1024) goto end ;
    // Ensure record length doesn't exceed bounds
    if (cursor + record_length > data_end) goto end;

    // TLS handshake header
    if (cursor + 1 > data_end || *((__u8 *)cursor) != 0x01) goto end; // ClientHello
    cursor += 4; // Skip handshake message type and length

    // Skip TLS version
    if (cursor + 2 > data_end) goto end;
    cursor += 2;

    // Skip random bytes (32 bytes)
    if (cursor + 32 > data_end) goto end;
    cursor += 32;

    // Skip session ID
    if (cursor + 1 > data_end) goto end;
    __u8 session_id_len = *((__u8 *)cursor);
    cursor += 1;
    if (cursor + session_id_len > data_end) goto end;
    cursor += session_id_len;

    // Skip cipher suites
    if (cursor + 2 > data_end) goto end;
    __u16 cipher_suites_len = bpf_ntohs(*(__u16 *)cursor);
    cursor += 2;
    if (cipher_suites_len > 254) goto end;
    if (cursor + cipher_suites_len > data_end) goto end;
    cursor += cipher_suites_len;

    // Skip compression methods
    if (cursor + 1 > data_end) goto end;

    __u8 compression_methods_len = *((__u8 *)cursor);
    cursor += 1;
    if (cursor + compression_methods_len > data_end) goto end;
    cursor += compression_methods_len;

    // check bound before get extension_method_len
    if (cursor + 2 > data_end) goto end;

    __u16 extension_method_len = *(__u16 *)cursor; //here use bpf_ntohs breaks SNI parsing, why?

    if (extension_method_len < 0) goto end;

    cursor += sizeof(__u16);

    for (int i = 0; i < 32; i++)
    {
        struct extension *ext;
	__u16 ext_len = 0;

        if (cursor > extension_method_len + data) goto end;

        if (data_end < (cursor + sizeof(*ext))) goto end;

        ext = (struct extension *)cursor;
	ext_len = bpf_ntohs(ext->len);

        cursor += sizeof(*ext);

        if (ext->type == SERVER_NAME_EXTENSION)
        {
            struct domain_name dn = {0};

            if (data_end < (cursor + sizeof(struct sni_extension))) goto end;

            struct sni_extension *sni = (struct sni_extension *)cursor;

            cursor += sizeof(struct sni_extension);

            __u16 server_name_len = bpf_ntohs(sni->len);

            //avoid invalid write to stack R1 off=0 size=1
            if (server_name_len >= sizeof(dn.server_name)) goto end;

            for (int sn_idx = 0; sn_idx < server_name_len; sn_idx++)
            {
                // invalid access to packet, off=11 size=1, R5(id=0,off=11,r=11)
                // R5 offset is outside of the packet
                if (data_end < cursor + sn_idx + 1) goto end;

                if (dn.server_name + sizeof(struct domain_name) < dn.server_name + sn_idx) goto end;


                dn.server_name[sn_idx] = ((char *)cursor)[sn_idx];
            }

            dn.server_name[MAX_DOMAIN_SIZE] = '\0';
	    dn.lpm_key.prefixlen = server_name_len * 8;

            bpf_printk("TLS SNI: %s", dn.server_name);

	    reverse_string(dn.server_name, server_name_len);

            if (bpf_map_lookup_elem(&sni_denylist, &dn)) {
                    bpf_printk("Domain %s found in denylist, dropping packet\n", dn.server_name);
                    return XDP_DROP;
            }

/*
	    __u8 value = 1;

	    if (bpf_map_update_elem(&sni_denylist, &dn, &value, BPF_ANY) < 0) {
			bpf_printk("Domain %s not updated in denylist\n", dn.server_name);
	    } else {
			bpf_printk("Domain %s updated in denylist\n", dn.server_name);
            }
*/

            goto end;
        }

        if (ext_len > 2048) goto end;

        if (data_end < cursor + ext_len) goto end;

        cursor += ext_len;
    }

end:
    return XDP_PASS;

}

char _license[] SEC("license") = "GPL";

