/*
 * Copyright (c) 2024, BPFire.  All rights reserved.
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

#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <syslog.h>

#define MAX_DOMAIN_SIZE 63

struct qname_event {
	__u8 len;
	__u32 src_ip; // IPv4 address
	char qname[MAX_DOMAIN_SIZE + 1];
};

// Helper function to convert DNS label to a standard domain format
void dns_label_to_dot_notation(char *dns_name, char *output, size_t len)
{
	size_t pos = 0, out_pos = 0;

	while (pos < len) {
		__u8 label_len = dns_name[pos];
		if (label_len == 0 || pos + label_len + 1 > len || out_pos + label_len >= MAX_DOMAIN_SIZE) {
			break; // Prevent buffer overflow
		}

		if (out_pos != 0) {
			output[out_pos++] = '.'; // Add a dot between labels
		}

		// Copy the label
		for (size_t i = 1; i <= label_len; i++) {
			output[out_pos++] = dns_name[pos + i];
		}

		pos += label_len + 1;
	}

	output[out_pos] = '\0'; // Null-terminate the result
}

// Corrected handle_event function to match the signature expected by ring_buffer__new
int handle_event(void *ctx __attribute__((unused)), void *data,
		 size_t data_sz)
{
	if (data_sz < sizeof(struct qname_event)) {
		syslog(LOG_ERR, "Unexpected data size: %zu", data_sz);
		return -1;
	}

	struct qname_event *event = (struct qname_event *)data;

	if (event->len > MAX_DOMAIN_SIZE) {
		syslog(LOG_ERR, "Invalid qname length: %u", event->len);
		return -1;
	}

	char src_ip_str[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &event->src_ip, src_ip_str, sizeof(src_ip_str))) {
		syslog(LOG_ERR, "Failed to convert source IP");
		return -1;
	}

	char domain_str[MAX_DOMAIN_SIZE + 1] = { 0 }; // +1 for null terminator
	dns_label_to_dot_notation(event->qname, domain_str, event->len);

	syslog(LOG_INFO, "Received qname: %s from source IP: %s", domain_str,
	       src_ip_str);

	return 0; // Return 0 to indicate success
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <path_to_ringbuf>\n", argv[0]);
		return 1;
	}

	const char *ringbuf_path = argv[1];
	struct ring_buffer *rb;
	int ringbuf_fd;

	openlog("qname_logger", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	// Open the ring buffer
	ringbuf_fd = bpf_obj_get(ringbuf_path);
	if (ringbuf_fd < 0) {
		perror("Failed to open ring buffer");
		return 1;
	}

	// Set up ring buffer polling with the corrected function signature
	rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
	if (!rb) {
		perror("Failed to create ring buffer");
		return 1;
	}

	// Poll the ring buffer
	while (1) {
		ring_buffer__poll(rb, -1); // Block indefinitely
	}

	ring_buffer__free(rb);
	closelog();
	return 0;
}

