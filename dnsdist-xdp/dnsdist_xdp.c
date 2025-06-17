#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "dnsdist_xdp.h"
#include "dnsdist_xdp.skel.h"

#define DROP_ACTION 1
#define TC_ACTION 2

/* Set this to 1 to enable XSK support, 0 to disable */
#define USE_XSK 1  // Change to 0 to disable XSK support

#if USE_XSK
#define UseXsk
#endif

struct blocked_item {
    char *value;
    int action;
};

struct blocked_qname {
    char *qname;
    char *qtype;
    int action;
};

static struct blocked_item *blocked_ipv4 = NULL;
static struct blocked_item *blocked_ipv6 = NULL;
static struct blocked_item *blocked_cidr4 = NULL;
static struct blocked_item *blocked_cidr6 = NULL;
static struct blocked_qname *blocked_qnames = NULL;

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i, --interface <iface>    Network interface to attach to (default: eth0)\n");
    printf("  --xsk                      Enable XSK (AF_XDP) mode\n");
    printf("  --ipv4 <ip>,[drop|tc]      Block IPv4 address (e.g., \"192.0.2.1,tc\")\n");
    printf("  --ipv6 <ip>,[drop|tc]      Block IPv6 address (e.g., \"2001:db8::1,drop\")\n");
    printf("  --cidr4 <cidr>,[drop|tc]   Block IPv4 CIDR (e.g., \"192.0.2.0/24,tc\")\n");
    printf("  --cidr6 <cidr>,[drop|tc]   Block IPv6 CIDR (e.g., \"2001:db8::/64,drop\")\n");
    printf("  --qname <name>,<type>,[drop|tc] Block DNS query (e.g., \"example.com,A,drop\")\n");
    printf("  -h, --help                 Show this help message\n");
}

static int parse_action(const char *action_str) {
    if (strcmp(action_str, "drop") == 0) return DROP_ACTION;
    if (strcmp(action_str, "tc") == 0) return TC_ACTION;
    return -1;
}

static int add_blocked_item(struct blocked_item **list, char *value, int action) {
    int count = 0;
    if (*list) {
        while ((*list)[count].value != NULL) count++;
    }

    struct blocked_item *new_list = realloc(*list, (count + 2) * sizeof(struct blocked_item));
    if (!new_list) return -1;

    new_list[count].value = strdup(value);
    new_list[count].action = action;
    new_list[count + 1].value = NULL;
    new_list[count + 1].action = 0;

    *list = new_list;
    return 0;
}

static int add_blocked_qname(char *qname, char *qtype, int action) {
    int count = 0;
    if (blocked_qnames) {
        while (blocked_qnames[count].qname != NULL) count++;
    }

    struct blocked_qname *new_list = realloc(blocked_qnames, (count + 2) * sizeof(struct blocked_qname));
    if (!new_list) return -1;

    new_list[count].qname = strdup(qname);
    new_list[count].qtype = strdup(qtype);
    new_list[count].action = action;
    new_list[count + 1].qname = NULL;
    new_list[count + 1].qtype = NULL;
    new_list[count + 1].action = 0;

    blocked_qnames = new_list;
    return 0;
}

static int parse_args(int argc, char **argv, char **ifname, bool *xsk_mode) {
    *ifname = "eth0";
    *xsk_mode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i-1]);
                return -1;
            }
            *ifname = argv[i];
        } 
        else if (strcmp(argv[i], "--xsk") == 0) {
            *xsk_mode = true;
        }
        else if (strcmp(argv[i], "--ipv4") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --ipv4 requires an argument\n");
                return -1;
            }
            char *comma = strchr(argv[i], ',');
            if (!comma) {
                fprintf(stderr, "Error: --ipv4 format should be IP,action\n");
                return -1;
            }
            *comma = '\0';
            int action = parse_action(comma + 1);
            if (action < 0) {
                fprintf(stderr, "Error: Invalid action for --ipv4 (use drop or tc)\n");
                return -1;
            }
            if (add_blocked_item(&blocked_ipv4, argv[i], action) < 0) {
                fprintf(stderr, "Error: Failed to add IPv4 rule\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--ipv6") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --ipv6 requires an argument\n");
                return -1;
            }
            char *comma = strchr(argv[i], ',');
            if (!comma) {
                fprintf(stderr, "Error: --ipv6 format should be IP,action\n");
                return -1;
            }
            *comma = '\0';
            int action = parse_action(comma + 1);
            if (action < 0) {
                fprintf(stderr, "Error: Invalid action for --ipv6 (use drop or tc)\n");
                return -1;
            }
            if (add_blocked_item(&blocked_ipv6, argv[i], action) < 0) {
                fprintf(stderr, "Error: Failed to add IPv6 rule\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--cidr4") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --cidr4 requires an argument\n");
                return -1;
            }
            char *comma = strchr(argv[i], ',');
            if (!comma) {
                fprintf(stderr, "Error: --cidr4 format should be CIDR,action\n");
                return -1;
            }
            *comma = '\0';
            int action = parse_action(comma + 1);
            if (action < 0) {
                fprintf(stderr, "Error: Invalid action for --cidr4 (use drop or tc)\n");
                return -1;
            }
            if (add_blocked_item(&blocked_cidr4, argv[i], action) < 0) {
                fprintf(stderr, "Error: Failed to add CIDR4 rule\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--cidr6") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --cidr6 requires an argument\n");
                return -1;
            }
            char *comma = strchr(argv[i], ',');
            if (!comma) {
                fprintf(stderr, "Error: --cidr6 format should be CIDR,action\n");
                return -1;
            }
            *comma = '\0';
            int action = parse_action(comma + 1);
            if (action < 0) {
                fprintf(stderr, "Error: Invalid action for --cidr6 (use drop or tc)\n");
                return -1;
            }
            if (add_blocked_item(&blocked_cidr6, argv[i], action) < 0) {
                fprintf(stderr, "Error: Failed to add CIDR6 rule\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--qname") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --qname requires an argument\n");
                return -1;
            }
            char *first_comma = strchr(argv[i], ',');
            if (!first_comma) {
                fprintf(stderr, "Error: --qname format should be name,type,action\n");
                return -1;
            }
            *first_comma = '\0';
            char *second_comma = strchr(first_comma + 1, ',');
            if (!second_comma) {
                fprintf(stderr, "Error: --qname format should be name,type,action\n");
                return -1;
            }
            *second_comma = '\0';
            int action = parse_action(second_comma + 1);
            if (action < 0) {
                fprintf(stderr, "Error: Invalid action for --qname (use drop or tc)\n");
                return -1;
            }
            if (add_blocked_qname(argv[i], first_comma + 1, action) < 0) {
                fprintf(stderr, "Error: Failed to add QNAME rule\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
        else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static void free_block_lists() {
    if (blocked_ipv4) {
        for (int i = 0; blocked_ipv4[i].value != NULL; i++) {
            free(blocked_ipv4[i].value);
        }
        free(blocked_ipv4);
    }
    if (blocked_ipv6) {
        for (int i = 0; blocked_ipv6[i].value != NULL; i++) {
            free(blocked_ipv6[i].value);
        }
        free(blocked_ipv6);
    }
    if (blocked_cidr4) {
        for (int i = 0; blocked_cidr4[i].value != NULL; i++) {
            free(blocked_cidr4[i].value);
        }
        free(blocked_cidr4);
    }
    if (blocked_cidr6) {
        for (int i = 0; blocked_cidr6[i].value != NULL; i++) {
            free(blocked_cidr6[i].value);
        }
        free(blocked_cidr6);
    }
    if (blocked_qnames) {
        for (int i = 0; blocked_qnames[i].qname != NULL; i++) {
            free(blocked_qnames[i].qname);
            free(blocked_qnames[i].qtype);
        }
        free(blocked_qnames);
    }
}

static int populate_maps(struct dnsdist_xdp *skel) {
    // Populate IPv4 filter
    if (blocked_ipv4) {
        for (int i = 0; blocked_ipv4[i].value != NULL; i++) {
            struct in_addr addr;
            if (inet_pton(AF_INET, blocked_ipv4[i].value, &addr) != 1) {
                fprintf(stderr, "Invalid IPv4 address: %s\n", blocked_ipv4[i].value);
                return -1;
            }
            
            uint32_t key = ntohl(addr.s_addr);
            struct map_value value = {
                .counter = 0,
                .action = blocked_ipv4[i].action
            };
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.v4filter), &key, &value, BPF_ANY)) {
                perror("Failed to update v4filter");
                return -1;
            }
        }
    }
    
    // Populate IPv6 filter
    if (blocked_ipv6) {
        for (int i = 0; blocked_ipv6[i].value != NULL; i++) {
            struct in6_addr addr;
            if (inet_pton(AF_INET6, blocked_ipv6[i].value, &addr) != 1) {
                fprintf(stderr, "Invalid IPv6 address: %s\n", blocked_ipv6[i].value);
                return -1;
            }
            
            struct map_value value = {
                .counter = 0,
                .action = blocked_ipv6[i].action
            };
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.v6filter), &addr, &value, BPF_ANY)) {
                perror("Failed to update v6filter");
                return -1;
            }
        }
    }
    
    // Populate CIDR4 filter
    if (blocked_cidr4) {
        for (int i = 0; blocked_cidr4[i].value != NULL; i++) {
            char *slash = strchr(blocked_cidr4[i].value, '/');
            if (!slash) {
                fprintf(stderr, "Invalid CIDR format: %s\n", blocked_cidr4[i].value);
                return -1;
            }
            
            *slash = '\0';
            struct in_addr addr;
            if (inet_pton(AF_INET, blocked_cidr4[i].value, &addr) != 1) {
                fprintf(stderr, "Invalid IPv4 address: %s\n", blocked_cidr4[i].value);
                return -1;
            }
            *slash = '/';
            
            int prefix_len = atoi(slash + 1);
            if (prefix_len < 0 || prefix_len > 32) {
                fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
                return -1;
            }
            
            struct CIDR4 key = {
                .cidr = prefix_len,
                .addr = addr.s_addr
            };
            
            struct map_value value = {
                .counter = 0,
                .action = blocked_cidr4[i].action
            };
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.cidr4filter), &key, &value, BPF_ANY)) {
                perror("Failed to update cidr4filter");
                return -1;
            }
        }
    }
    
    // Populate CIDR6 filter
    if (blocked_cidr6) {
        for (int i = 0; blocked_cidr6[i].value != NULL; i++) {
            char *slash = strchr(blocked_cidr6[i].value, '/');
            if (!slash) {
                fprintf(stderr, "Invalid CIDR format: %s\n", blocked_cidr6[i].value);
                return -1;
            }
            
            *slash = '\0';
            struct in6_addr addr;
            if (inet_pton(AF_INET6, blocked_cidr6[i].value, &addr) != 1) {
                fprintf(stderr, "Invalid IPv6 address: %s\n", blocked_cidr6[i].value);
                return -1;
            }
            *slash = '/';
            
            int prefix_len = atoi(slash + 1);
            if (prefix_len < 0 || prefix_len > 128) {
                fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
                return -1;
            }
            
            struct CIDR6 key = {
                .cidr = prefix_len,
                .addr = addr
            };
            
            struct map_value value = {
                .counter = 0,
                .action = blocked_cidr6[i].action
            };
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.cidr6filter), &key, &value, BPF_ANY)) {
                perror("Failed to update cidr6filter");
                return -1;
            }
        }
    }
    
    // Populate QName filter
    if (blocked_qnames) {
        for (int i = 0; blocked_qnames[i].qname != NULL; i++) {
            struct dns_qname key = {0};
            uint8_t *qname_ptr = key.qname;
            const char *qname = blocked_qnames[i].qname;
            
            const char *dot = qname;
            while ((dot = strchr(qname, '.'))) {
                size_t len = dot - qname;
                if (len > 63) {
                    fprintf(stderr, "Label too long: %s\n", qname);
                    return -1;
                }
                
                *qname_ptr++ = len;
                for (size_t j = 0; j < len; j++) {
                    char c = qname[j];
                    if (c >= 'A' && c <= 'Z') {
                        c += 'a' - 'A';
                    }
                    *qname_ptr++ = c;
                }
                
                qname = dot + 1;
            }
            
            size_t len = strlen(qname);
            if (len > 63) {
                fprintf(stderr, "Label too long: %s\n", qname);
                return -1;
            }
            
            *qname_ptr++ = len;
            for (size_t j = 0; j < len; j++) {
                char c = qname[j];
                if (c >= 'A' && c <= 'Z') {
                    c += 'a' - 'A';
                }
                *qname_ptr++ = c;
            }
            *qname_ptr = 0;
            
            if (strcmp(blocked_qnames[i].qtype, "*") == 0) {
                key.qtype = htons(65535);
            } else {
                key.qtype = htons(1); // Default to A record if not found
            }
            
            struct map_value value = {
                .counter = 0,
                .action = blocked_qnames[i].action
            };
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.qnamefilter), &key, &value, BPF_ANY)) {
                perror("Failed to update qnamefilter");
                return -1;
            }
        }
    }
    
    return 0;
}

static struct dnsdist_xdp *skel = NULL;

static void cleanup(int sig __attribute__((unused))) {
    printf("\nCleaning up...\n");

    if (skel) {
        dnsdist_xdp__destroy(skel);
        skel = NULL;
    }

    exit(0);
}

static int pin_map(struct bpf_map *map, const char *path) {
    int err;

    // Try to open existing map first
    int map_fd = bpf_obj_get(path);
    if (map_fd >= 0) {
        close(map_fd);
        return 0; // Map already exists and is pinned
    }

    // Pin new map
    err = bpf_map__pin(map, path);
    if (err) {
        fprintf(stderr, "Failed to pin map %s to %s: %s\n",
                bpf_map__name(map), path, strerror(errno));
        return err;
    }

    return 0;
}

static int setup_bpf_maps(struct dnsdist_xdp *skel) {
    // Create BPF filesystem mount point if it doesn't exist
    if (mkdir("/sys/fs/bpf/dnsdist", 0755) && errno != EEXIST) {
        fprintf(stderr, "Failed to create BPF mount point: %s\n", strerror(errno));
        return -1;
    }

    // Pin regular maps (non-XSK)
    const struct {
        const char *name;
        const char *path;
    } regular_maps[] = {
        {bpf_map__name(skel->maps.v4filter), "/sys/fs/bpf/dnsdist/addr-v4"},
        {bpf_map__name(skel->maps.v6filter), "/sys/fs/bpf/dnsdist/addr-v6"},
        {bpf_map__name(skel->maps.qnamefilter), "/sys/fs/bpf/dnsdist/qnames"},
        {bpf_map__name(skel->maps.cidr4filter), "/sys/fs/bpf/dnsdist/cidr4"},
        {bpf_map__name(skel->maps.cidr6filter), "/sys/fs/bpf/dnsdist/cidr6"},
        {NULL, NULL}
    };

    for (int i = 0; regular_maps[i].name != NULL; i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, regular_maps[i].name);
        if (!map) {
            fprintf(stderr, "Failed to find map %s\n", regular_maps[i].name);
            return -1;
        }
        if (pin_map(map, regular_maps[i].path)) {
            return -1;
        }
    }

    return 0;
}

#ifdef UseXsk
static int setup_xsk_maps(struct dnsdist_xdp *skel, const char *ifname) {

    const struct {
        const char *name;
        const char *path;
    } xsk_maps[] = {
        {bpf_map__name(skel->maps.xsk_map), "/sys/fs/bpf/dnsdist/xskmap"},
        {bpf_map__name(skel->maps.xskDestinationsV4), "/sys/fs/bpf/dnsdist/xsk-destinations-v4"},
        {bpf_map__name(skel->maps.xskDestinationsV6), "/sys/fs/bpf/dnsdist/xsk-destinations-v6"},
        {NULL, NULL}
    };

    for (int i = 0; xsk_maps[i].name != NULL; i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, xsk_maps[i].name);
        if (!map) {
            fprintf(stderr, "Failed to find XSK map %s\n", xsk_maps[i].name);
            return -1;
        }
        if (pin_map(map, xsk_maps[i].path)) {
            return -1;
        }
    }

    // Add default destination (the interface's IP)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            struct IPv4AndPort key = {
                .addr = sin->sin_addr.s_addr,
                .port = htons(53)
            };
            bool value = true;
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.xskDestinationsV4), 
                                   &key, &value, BPF_ANY)) {
                fprintf(stderr, "Failed to add IPv4 XSK destination\n");
                freeifaddrs(ifaddr);
                return -1;
            }
        } 
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            struct IPv6AndPort key = {
                .port = htons(53)
            };
            memcpy(&key.addr, &sin6->sin6_addr, sizeof(key.addr));
            bool value = true;
            
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.xskDestinationsV6), 
                                   &key, &value, BPF_ANY)) {
                fprintf(stderr, "Failed to add IPv6 XSK destination\n");
                freeifaddrs(ifaddr);
                return -1;
            }
        }
    }
    
    freeifaddrs(ifaddr);

    return 0;
}
#endif

int main(int argc, char **argv) {
    struct dnsdist_xdp *skel;
    int err;
    char *ifname;
    bool xsk_mode;

    // Parse command line arguments
    if (parse_args(argc, argv, &ifname, &xsk_mode) < 0) {
        print_usage(argv[0]);
        return 1;
    }

    // Get interface index
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", 
                ifname, strerror(errno));
        free_block_lists();
        return 1;
    }

    // Set up signal handler for clean exit
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // Load and verify BPF application
    skel = dnsdist_xdp__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        free_block_lists();
        return 1;
    }
    
    // Set any BPF program variables here
    if (xsk_mode) {
        bpf_program__set_autoload(skel->progs.xdp_dns_filter, true);
    } else {
        bpf_program__set_autoload(skel->progs.xdp_dns_filter, true);
    }
    
    // Load BPF program
    err = dnsdist_xdp__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
	cleanup(0);
        free_block_lists();
        return 1;
    }
    

    // Setup regular BPF maps
    if (setup_bpf_maps(skel) < 0) {
        fprintf(stderr, "Failed to setup BPF maps\n");
	cleanup(0);
        free_block_lists();
        return 1;
    }
    
    // Setup XSK maps if in XSK mode
    if (xsk_mode) {
#ifdef UseXsk
        if (setup_xsk_maps(skel, ifname) < 0) {
            fprintf(stderr, "Failed to setup XSK maps\n");
	    cleanup(0);
            free_block_lists();
            return 1;
        }
#endif
    }
 
    // Populate BPF maps
    if (populate_maps(skel) < 0) {
        fprintf(stderr, "Failed to populate BPF maps\n");
	cleanup(0);
        free_block_lists();
        return 1;
    }
    
    // Attach XDP program
    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_dns_filter, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach BPF program to interface %s\n", ifname);
        dnsdist_xdp__destroy(skel);
        free_block_lists();
        return 1;
    }
    
    printf("XDP filter successfully loaded on interface %s\n", ifname);
    if (xsk_mode) {
        printf("XSK (AF_XDP) mode enabled\n");
    }
    
    // Print loaded rules
    printf("Loaded blocking rules:\n");
    if (blocked_ipv4) {
        for (int i = 0; blocked_ipv4[i].value != NULL; i++) {
            printf("  IPv4: %s -> %s\n", blocked_ipv4[i].value, 
                  blocked_ipv4[i].action == DROP_ACTION ? "DROP" : "TC");
        }
    }
    if (blocked_ipv6) {
        for (int i = 0; blocked_ipv6[i].value != NULL; i++) {
            printf("  IPv6: %s -> %s\n", blocked_ipv6[i].value, 
                  blocked_ipv6[i].action == DROP_ACTION ? "DROP" : "TC");
        }
    }
    if (blocked_cidr4) {
        for (int i = 0; blocked_cidr4[i].value != NULL; i++) {
            printf("  CIDR4: %s -> %s\n", blocked_cidr4[i].value, 
                  blocked_cidr4[i].action == DROP_ACTION ? "DROP" : "TC");
        }
    }
    if (blocked_cidr6) {
        for (int i = 0; blocked_cidr6[i].value != NULL; i++) {
            printf("  CIDR6: %s -> %s\n", blocked_cidr6[i].value, 
                  blocked_cidr6[i].action == DROP_ACTION ? "DROP" : "TC");
        }
    }
    if (blocked_qnames) {
        for (int i = 0; blocked_qnames[i].qname != NULL; i++) {
            printf("  QNAME: %s/%s -> %s\n", blocked_qnames[i].qname, 
                  blocked_qnames[i].qtype,
                  blocked_qnames[i].action == DROP_ACTION ? "DROP" : "TC");
        }
    }
    
    // Wait for interrupt to exit
    printf("\nPress Ctrl-C to exit...\n");
    pause();
    
    // Clean up
    bpf_link__destroy(link);
    dnsdist_xdp__destroy(skel);
    free_block_lists();
    
    return 0;
}
