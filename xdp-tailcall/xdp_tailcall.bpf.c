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
#define MAX_DOMAIN_SIZE 63

// Program identifiers for the array map
#define PROG_SNI_INDEX 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);  // Hash map for SNI denylist
    __type(key, char[MAX_DOMAIN_SIZE + 1]);  // Server name as the key
    __type(value, __u8);  // Value could be anything (e.g., 1 for blacklisted)
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12); // 4KB buffer
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sni_ringbuf SEC(".maps");

struct sni_event {
	__u8 len;
	__u32 src_ip; // Store IPv4 address
	char sni[MAX_DOMAIN_SIZE + 1];
};

SEC("xdp")
int xdp_tls_sni(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *cursor = data;

	// Parse Ethernet header
	struct ethhdr *eth = cursor;
	if (cursor + sizeof(*eth) > data_end)
		goto end;
	cursor += sizeof(*eth);

	// Only process IPv4 packets
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto end;

	// Parse IP header
	struct iphdr *ip = cursor;
	if (cursor + sizeof(*ip) > data_end)
		goto end;
	cursor += ip->ihl * 4; // IP header length in 32-bit words

	// Only process TCP traffic
	if (ip->protocol != IPPROTO_TCP)
		goto end;

	// Parse TCP header
	struct tcphdr *tcp = cursor;
	if (cursor + sizeof(*tcp) > data_end)
		goto end;
	cursor += tcp->doff * 4; // TCP header length in 32-bit words

	// Only process traffic on port 443 (HTTPS)
	if (tcp->dest != bpf_htons(443))
		goto end;

	// Check if there's enough data for the TLS ClientHello
	if (data_end < cursor + 5)
		goto end;

	// TLS record header
	__u8 record_type = *((__u8 *)cursor);
	__u16 tls_version = bpf_ntohs(*(__u16 *)(cursor + 1));
	__u16 record_length = bpf_ntohs(*(__u16 *)(cursor + 3));

	if (record_type != 0x16 || tls_version < 0x0301)
		goto end; // Only handshake and TLSv1.0+
	cursor += 5;

	if (record_length > 1024)
		goto end;
	// Ensure record length doesn't exceed bounds
	if (cursor + record_length > data_end)
		goto end;

	// TLS handshake header
	if (cursor + 1 > data_end || *((__u8 *)cursor) != 0x01)
		goto end; // ClientHello
	cursor += 4; // Skip handshake message type and length

	// Skip TLS version
	if (cursor + 2 > data_end)
		goto end;
	cursor += 2;

	// Skip random bytes (32 bytes)
	if (cursor + 32 > data_end)
		goto end;
	cursor += 32;

	// Skip session ID
	if (cursor + 1 > data_end)
		goto end;
	__u8 session_id_len = *((__u8 *)cursor);
	cursor += 1;
	if (cursor + session_id_len > data_end)
		goto end;
	cursor += session_id_len;

	// Skip cipher suites
	if (cursor + 2 > data_end)
		goto end;
	__u16 cipher_suites_len = bpf_ntohs(*(__u16 *)cursor);
	cursor += 2;
	if (cipher_suites_len > 254)
		goto end;
	if (cursor + cipher_suites_len > data_end)
		goto end;
	cursor += cipher_suites_len;

	// Skip compression methods
	if (cursor + 1 > data_end)
		goto end;

	__u8 compression_methods_len = *((__u8 *)cursor);
	cursor += 1;
	if (cursor + compression_methods_len > data_end)
		goto end;
	cursor += compression_methods_len;

	// check bound before get extension_method_len
	if (cursor + 2 > data_end)
		goto end;

	__u16 extension_method_len =
		*(__u16 *)cursor; //here use bpf_ntohs breaks SNI parsing, why?

	if (extension_method_len < 0)
		goto end;

	cursor += sizeof(__u16);

	for (int i = 0; i < 32; i++) {
		struct extension *ext;
		__u16 ext_len = 0;

		if (cursor > extension_method_len + data)
			goto end;

		if (data_end < (cursor + sizeof(*ext)))
			goto end;

		ext = (struct extension *)cursor;
		ext_len = bpf_ntohs(ext->len);

		cursor += sizeof(*ext);

		if (ext->type == SERVER_NAME_EXTENSION) {
			// Allocate a buffer from the ring buffer
			struct sni_event *event = bpf_ringbuf_reserve( &sni_ringbuf, sizeof(*event), 0);
			if (!event)
				goto end; // Drop if no space

			char server_name[MAX_DOMAIN_SIZE + 1] = {0};  // Allocate server name buffer

			if (data_end < (cursor + sizeof(struct sni_extension))) {
				bpf_ringbuf_discard(event, 0);
				goto end;
			}

			struct sni_extension *sni = (struct sni_extension *)cursor;

			cursor += sizeof(struct sni_extension);

			__u16 server_name_len = bpf_ntohs(sni->len);

			if (server_name_len >= sizeof(server_name)) {
				bpf_ringbuf_discard(event, 0);
				goto end;
			}

			for (int sn_idx = 0; sn_idx < server_name_len; sn_idx++) {
				if (data_end < cursor + sn_idx + 1) {
					bpf_ringbuf_discard(event, 0);
					goto end;
				}

				server_name[sn_idx] = ((char *)cursor)[sn_idx];
				event->sni[sn_idx] = ((char *)cursor)[sn_idx];
			}

			event->sni[MAX_DOMAIN_SIZE] = '\0';
			event->len = server_name_len;
			event->src_ip = ip->saddr;

			bpf_ringbuf_submit(event, 0);

			server_name[MAX_DOMAIN_SIZE] = '\0';

			bpf_printk("TLS SNI: %s", server_name);

			if (bpf_map_lookup_elem(&sni_denylist, &server_name)) {
				bpf_printk(
					"Domain %s found in denylist, dropping packet\n",
					server_name);
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

		if (ext_len > 2048)
			goto end;

		if (data_end < cursor + ext_len)
			goto end;

		cursor += ext_len;
	}

end:
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __array(values, int (void *));
} tail_call_array SEC(".maps") = {
        .values = {
                [PROG_SNI_INDEX] = (void *)&xdp_tls_sni,
        },
};

// Main XDP program
SEC("xdp")
int xdp_tailcall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Check packet bounds
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // Check if destination port is 443 (HTTPS)
        if (tcp->dest == bpf_htons(443)) {
            // Tail call the SNI program
            bpf_tail_call(ctx, &tail_call_array, PROG_SNI_INDEX);
            return XDP_ABORTED; // Should not reach here if tail call succeeds
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
