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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define MAX_DOMAIN_SIZE 128  // Increased size to handle larger domains

struct domain_key {
    struct bpf_lpm_trie_key lpm_key;
    char data[MAX_DOMAIN_SIZE + 1];
};

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

static void reverse_string(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len / 2; i++) {
        char temp = str[i];
        str[i] = str[len - i - 1];
        str[len - i - 1] = temp;
    }
}

int main(int argc, char *argv[]) {
    int map_fd;
    struct domain_key dkey = {0};
    __u8 value = 1;

    // Check for proper number of arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <add|delete> <domain>\n", argv[0]);
        return 1;
    }

    // Encode the domain name with label lengths
    encode_domain(argv[2], dkey.data);
    reverse_string(dkey.data);

    // Set the LPM trie key prefix length
    dkey.lpm_key.prefixlen = strlen(dkey.data) * 8;

    // Open the BPF map
    map_fd = bpf_obj_get("/sys/fs/bpf/xdp-dns/domain_denylist");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return 1;
    }

    // Add or delete the domain based on the first argument
    if (strcmp(argv[1], "add") == 0) {
        // Update the map with the encoded domain name
        if (bpf_map_update_elem(map_fd, &dkey, &value, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to add domain to map: %s\n", strerror(errno));
            return 1;
        }
        printf("Domain %s added to denylist\n", argv[2]);
    } else if (strcmp(argv[1], "delete") == 0) {
        // Remove the domain from the map
        if (bpf_map_delete_elem(map_fd, &dkey) != 0) {
            fprintf(stderr, "Failed to remove domain from map: %s\n", strerror(errno));
            return 1;
        }
        printf("Domain %s removed from denylist\n", argv[2]);
    } else {
        fprintf(stderr, "Invalid command: %s. Use 'add' or 'delete'.\n", argv[1]);
        return 1;
    }

    return 0;
}
