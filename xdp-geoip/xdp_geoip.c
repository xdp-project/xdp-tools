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
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define MAP_PATH "/sys/fs/bpf/xdp-geoip/geoip_map"
#define BATCH_SIZE 1000  // Number of entries per batch

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 saddr;
};

// Structure for country code and action
struct ip_entry {
    struct ipv4_lpm_key key;
    __u8 action;
};

void add_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    struct ipv4_lpm_key keys[BATCH_SIZE];
    __u8 actions[BATCH_SIZE];
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].key;
        actions[i] = entries[i].action;
    }

    __u32 num_entries = count;
    int ret = bpf_map_update_batch(map_fd, keys, actions, &num_entries, NULL);
    if (ret) {
        fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
    } else {
        printf("Batch update successful\n");
    }
}

void delete_ips_batch(int map_fd, struct ip_entry *entries, size_t count) {
    struct ipv4_lpm_key keys[BATCH_SIZE];
    for (size_t i = 0; i < count; i++) {
        keys[i] = entries[i].key;
    }

    __u32 num_entries = count;
    int ret = bpf_map_delete_batch(map_fd, keys, &num_entries, NULL);
    if (ret) {
        fprintf(stderr, "Batch delete failed: %s\n", strerror(errno));
    } else {
        printf("Batch delete successful\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s add|delete <ip_file.txt> <country_code>\n", argv[0]);
        return 1;
    }

    char *command = argv[1];  // "add" or "delete"
    char *file_path = argv[2];  // File with IP entries
    char *enabled_country = argv[3];  // Country code provided from web interface

    // Open the BPF map
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("fopen");
        return 1;
    }

    struct ip_entry entries[BATCH_SIZE];
    size_t count = 0;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // Process only lines that start with "add " and match the given country code
        if (strncmp(line, "add ", 4) == 0) {
            char *country_code = strtok(line + 4, "v");  // Extract the country code
            strtok(NULL, " ");  // Skip the next token ("hash")
            char *ip_str = strtok(NULL, " /");  // Extract the IP address
            char *prefix_str = strtok(NULL, " ");  // Extract the prefix length

            // If country code matches the enabled country, add or delete the IP
            if (country_code && strcmp(country_code, enabled_country) == 0) {
                if (ip_str && prefix_str) {
                    entries[count].key.prefixlen = atoi(prefix_str);
                    inet_pton(AF_INET, ip_str, &entries[count].key.saddr);

                    if (strcmp(command, "add") == 0) {
                        // Assuming we block IPs from enabled country
                        entries[count].action = 1;  // Block
                    }

                    count++;

                    // Process the batch if full
                    if (count == BATCH_SIZE) {
                        if (strcmp(command, "add") == 0) {
                            add_ips_batch(map_fd, entries, count);
                        } else if (strcmp(command, "delete") == 0) {
                            delete_ips_batch(map_fd, entries, count);
                        }
                        count = 0;
                    }
                }
            }
        }
    }

    // Process any remaining IPs in the last batch
    if (count > 0) {
        if (strcmp(command, "add") == 0) {
            add_ips_batch(map_fd, entries, count);
        } else if (strcmp(command, "delete") == 0) {
            delete_ips_batch(map_fd, entries, count);
        }
    }

    fclose(file);
    close(map_fd);
    return 0;
}
