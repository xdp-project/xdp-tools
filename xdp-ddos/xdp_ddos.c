#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int add_prog_to_map(const char *obj_path, const char *prog_name, const char *map_pin_path, __u32 key) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int map_fd = -1, prog_fd = -1;
    int err = -1;

    // Load BPF object
    obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object: %s\n", strerror(errno));
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "Program '%s' not found\n", prog_name);
        goto cleanup;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }

    map_fd = bpf_obj_get(map_pin_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map '%s': %s\n", map_pin_path, strerror(errno));
        goto cleanup;
    }

    // Insert program into map
    err = bpf_map_update_elem(map_fd, &key, &prog_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update map: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Added program '%s' to map '%s' at key %u\n", prog_name, map_pin_path, key);

cleanup:
    if (map_fd >= 0) close(map_fd);
    if (obj) bpf_object__close(obj);
    return err;
}

static int del_prog_from_map(const char *map_pin_path, __u32 key) {
    int map_fd, err;
    __u32 key_buf = key;

    map_fd = bpf_obj_get(map_pin_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open map: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_map_delete_elem(map_fd, &key_buf);

    if (err) {
        fprintf(stderr, "Delete failed: %s\n", strerror(errno));
    } else {
        printf("Deleted key %u\n", key);
    }

    close(map_fd);
    return err;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  Add: %s add <BPF_OBJECT_FILE> <PROG_NAME> <MAP_PIN_PATH> <KEY>\n"
            "  Del: %s del <MAP_PIN_PATH> <KEY>\n"
            "Example:\n"
            "  Add: %s add tcp_ddos.o xdp_tcp_ddos /sys/fs/bpf/ddos_progs 0\n"
            "  Del: %s del /sys/fs/bpf/ddos_progs 0\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add") == 0) {
        if (argc != 6) {
            fprintf(stderr, "Error: 'add' requires 5 arguments\n");
            return 1;
        }
        const char *obj_path = argv[2];
        const char *prog_name = argv[3];
        const char *map_pin_path = argv[4];
        __u32 key = (__u32)atoi(argv[5]);
        return add_prog_to_map(obj_path, prog_name, map_pin_path, key);

    } else if (strcmp(argv[1], "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: 'del' requires 2 arguments\n");
            return 1;
        }
        const char *map_pin_path = argv[2];
        __u32 key = (__u32)atoi(argv[3]);
        return del_prog_from_map(map_pin_path, key);

    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
}
