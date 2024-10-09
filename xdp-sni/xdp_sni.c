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

#define MAX_DOMAIN_SIZE 63 

int main(int argc, char *argv[])
{
	int map_fd;
	char server_name[MAX_DOMAIN_SIZE + 1] = {0};
	__u8 value = 1;

	// Check for proper number of arguments
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <add|delete> <domain>\n", argv[0]);
		return 1;
	}

	// Reverse the input domain
	strncpy(server_name, argv[2], MAX_DOMAIN_SIZE);
	server_name[MAX_DOMAIN_SIZE] = '\0'; // Ensure null termination

	// Open the BPF map
	map_fd = bpf_obj_get("/sys/fs/bpf/xdp-sni/sni_denylist");
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
		return 1;
	}

	// Add or delete the domain based on the first argument
	if (strcmp(argv[1], "add") == 0) {
		// Update the map with the reversed domain name
		if (bpf_map_update_elem(map_fd, server_name, &value, BPF_ANY) != 0) {
			fprintf(stderr, "Failed to add domain to map: %s\n",
				strerror(errno));
			return 1;
		}
		printf("Domain %s (reversed: %s) added to denylist\n", argv[2],
		       server_name);
	} else if (strcmp(argv[1], "delete") == 0) {
		// Remove the reversed domain from the map
		if (bpf_map_delete_elem(map_fd, server_name) != 0) {
			fprintf(stderr,
				"Failed to remove domain from map: %s\n",
				strerror(errno));
			return 1;
		}
		printf("Domain %s (reversed: %s) removed from denylist\n",
		       argv[2], server_name);
	} else {
		fprintf(stderr, "Invalid command: %s. Use 'add' or 'delete'.\n",
			argv[1]);
		return 1;
	}

	return 0;
}
