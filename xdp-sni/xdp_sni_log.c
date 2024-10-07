#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <syslog.h>

#define MAX_DOMAIN_SIZE 63

struct sni_event {
	__u8 len;
	__u32 src_ip; // IPv4 address
	char sni[MAX_DOMAIN_SIZE + 1];
};

// No need for DNS label to dot notation for SNI.
// Instead, just copy the SNI directly for logging.
void copy_sni(char *sni, char *output, size_t len)
{
	if (len > MAX_DOMAIN_SIZE) {
		len = MAX_DOMAIN_SIZE; // Ensure we don't overflow
	}
	// Directly copy the SNI string
	for (size_t i = 0; i < len; i++) {
		output[i] = sni[i];
	}
	output[len] = '\0'; // Null-terminate
}

// Corrected handle_event function to match the signature expected by ring_buffer__new
int handle_event(void *ctx __attribute__((unused)), void *data,
		 size_t data_sz __attribute__((unused)))
{
	struct sni_event *event = (struct sni_event *)data;

	char src_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &event->src_ip, src_ip_str, sizeof(src_ip_str));

	char domain_str[MAX_DOMAIN_SIZE + 1] = { 0 }; // Buffer for SNI
	copy_sni(event->sni, domain_str, event->len);

	syslog(LOG_INFO, "Received SNI: %s from source IP: %s", domain_str,
	       src_ip_str);

	return 0; // Return 0 to indicate success
}

int main()
{
	struct ring_buffer *rb;
	int ringbuf_fd;

	openlog("sni_logger", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	// Open the ring buffer
	ringbuf_fd = bpf_obj_get("/sys/fs/bpf/xdp-sni/sni_ringbuf");
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
