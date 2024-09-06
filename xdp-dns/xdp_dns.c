#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define MAX_DOMAIN_SIZE 128  // Increased size to handle larger domains

// Function to encode a domain name with label lengths
static void encode_domain(const char *domain, char *encoded) {
    const char *ptr = domain;
    char *enc_ptr = encoded;
    size_t label_len;

    while (*ptr) {
        // Find the length of the current label
        label_len = strcspn(ptr, ".");
        if (label_len > 0) {
            // Set the length of the label
            *enc_ptr++ = (char)label_len;
            // Copy the label itself
            memcpy(enc_ptr, ptr, label_len);
            enc_ptr += label_len;
        }
        // Move to the next label
        ptr += label_len;
        if (*ptr == '.') {
            ptr++; // Skip the dot
        }
    }
    // Append a zero-length label to mark the end of the domain name
    *enc_ptr++ = 0;
}

int main(int argc, char *argv[]) {
    int map_fd;
    char domain_key[MAX_DOMAIN_SIZE + 1] = {0};
    __u8 value = 1;

    // Check for proper number of arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <domain>\n", argv[0]);
        return 1;
    }

    // Encode the domain name with label lengths
    encode_domain(argv[1], domain_key);

    // Open the BPF map
    map_fd = bpf_obj_get("/sys/fs/bpf/xdp-dns/domain_denylist");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return 1;
    }

    // Update the map with the encoded domain name
    if (bpf_map_update_elem(map_fd, domain_key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update map: %s\n", strerror(errno));
        return 1;
    }

    printf("Domain %s added to denylist\n", argv[1]);
    return 0;
}

