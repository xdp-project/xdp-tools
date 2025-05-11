/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#define PROG_NAME "tc-loader"

typedef enum {
    TC_INGRESS,
    TC_EGRESS
} tc_direction;

static const struct loadopt {
    bool help;
    struct iface iface;
    struct multistring filenames;
    char *pin_path;
    char *section_name;
    char *prog_name;
    tc_direction direction;
    __u32 prio;
    __u32 handle;
} defaults_load = {
    .direction = TC_INGRESS,
    .prio = 0,
    .handle = 0,
};

struct enum_val tc_directions[] = {
    {"ingress", TC_INGRESS},
    {"egress", TC_EGRESS},
    {NULL, 0}
};

static struct prog_option load_options[] = {
    DEFINE_OPTION("direction", OPT_ENUM, struct loadopt, direction,
                  .short_opt = 'd',
                  .typearg = tc_directions,
                  .metavar = "<direction>",
                  .help = "Attach TC program in <direction> (ingress/egress); default ingress"),
    DEFINE_OPTION("pin-path", OPT_STRING, struct loadopt, pin_path,
                  .short_opt = 'p',
                  .help = "Path to pin maps under (must be in bpffs)."),
    DEFINE_OPTION("section", OPT_STRING, struct loadopt, section_name,
                  .metavar = "<section>",
                  .short_opt = 's',
                  .help = "ELF section name of program to load (default: first in file)."),
    DEFINE_OPTION("prog-name", OPT_STRING, struct loadopt, prog_name,
                  .metavar = "<prog_name>",
                  .short_opt = 'n',
                  .help = "BPF program name of program to load (default: first in file)."),
    DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
                  .positional = true,
                  .metavar = "<ifname>",
                  .required = true,
                  .help = "Load on device <ifname>"),
    DEFINE_OPTION("filenames", OPT_MULTISTRING, struct loadopt, filenames,
                  .positional = true,
                  .metavar = "<filename>",
                  .required = true,
                  .help = "Load program from <filename>"),
    DEFINE_OPTION("prio", OPT_U32, struct loadopt, prio,
                  .short_opt = 'P',
                  .help = "Set priority of TC filter"),
    DEFINE_OPTION("handle", OPT_U32, struct loadopt, handle,
                  .short_opt = 'H',
                  .help = "Set handle of TC filter (default 0)"),
    END_OPTIONS
};

static struct bpf_program *find_program(struct bpf_object *obj, const char *section, const char *name) {
    struct bpf_program *prog = NULL;
    struct bpf_program *tmp;

    if (name) {
        prog = bpf_object__find_program_by_name(obj, name);
        if (!prog)
            pr_warn("Program '%s' not found\n", name);
        return prog;
    }

    if (section) {
        bpf_object__for_each_program(tmp, obj) {
            const char *sec = bpf_program__section_name(tmp);
            if (sec && strcmp(sec, section) == 0) {
                prog = tmp;
                break;
            }
        }
        if (!prog)
            pr_warn("Section '%s' not found\n", section);
        return prog;
    }

    prog = bpf_object__next_program(obj, NULL);
    if (!prog)
        pr_warn("No programs found in object\n");
    return prog;
}

int do_load(const void *cfg, __unused const char *pin_root_path) {
    const struct loadopt *opt = cfg;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    char errmsg[STRERR_BUFSIZE];
    int err = 0;
    size_t num_progs;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
        .pin_root_path = opt->pin_path,
    );

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = opt->iface.ifindex,
        .attach_point = opt->direction == TC_INGRESS ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );

    num_progs = opt->filenames.num_strings;
    if (num_progs != 1) {
        pr_warn("Exactly one filename required\n");
        return EXIT_FAILURE;
    }

    const char *filename = opt->filenames.strings[0];

    obj = bpf_object__open_file(filename, &open_opts);
    if (libbpf_get_error(obj)) {
        pr_warn("Failed to open BPF object '%s'\n", filename);
        return EXIT_FAILURE;
    }

    if (!opt->pin_path) {
        struct bpf_map *map;
        bpf_object__for_each_map(map, obj) {
            bpf_map__set_pin_path(map, NULL);
        }
    }

    prog = find_program(obj, opt->section_name, opt->prog_name);
    if (!prog) {
        err = EXIT_FAILURE;
        goto out;
    }

    err = bpf_object__load(obj);
    if (err) {
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Load failed: %s\n", errmsg);
        goto out;
    }

    /* Create opts *after* loading so we get a valid prog_fd */
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(prog),
        .priority = opt->prio,
        .handle = opt->handle,
	.flags = BPF_TC_F_REPLACE,
    );

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        pr_warn("Failed to create TC hook: %s\n", strerror(-err));
        goto out;
    }

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        pr_warn("Failed to attach TC program: %s\n", strerror(-err));
        goto out_hook;
    }

    pr_info("TC program attached to %s %s (prio %u handle %u)\n",
            opt->iface.ifname,
            opt->direction == TC_INGRESS ? "ingress" : "egress",
            opt->prio, opt->handle);

    return EXIT_SUCCESS;

out_hook:
    bpf_tc_hook_destroy(&hook);
out:
    bpf_object__close(obj);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static const struct unloadopt {
    struct iface iface;
    tc_direction direction;
    __u32 prio;
    __u32 handle;
} defaults_unload = {};

static struct prog_option unload_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
                  .positional = true,
                  .metavar = "<ifname>",
                  .required = true,
                  .help = "Unload from device <ifname>"),
    DEFINE_OPTION("direction", OPT_ENUM, struct unloadopt, direction,
                  .short_opt = 'd',
                  .typearg = tc_directions,
                  .metavar = "<direction>",
                  .required = true,
                  .help = "TC direction (ingress/egress)"),
    DEFINE_OPTION("prio", OPT_U32, struct unloadopt, prio,
                  .short_opt = 'P',
                  .required = true,
                  .help = "Priority of TC filter to unload"),
    DEFINE_OPTION("handle", OPT_U32, struct unloadopt, handle,
                  .short_opt = 'H',
                  .required = true,
                  .help = "Handle of TC filter to unload"),
    END_OPTIONS
};

int do_unload(const void *cfg, __unused const char *pin_root_path) {
    const struct unloadopt *opt = cfg;
    int err;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = opt->iface.ifindex,
        .attach_point = opt->direction == TC_INGRESS ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .priority = opt->prio,
        .handle = opt->handle,
    );

    err = bpf_tc_detach(&hook, &opts);
    if (err) {
        pr_warn("Failed to detach TC program: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }

    pr_info("TC program detached from %s %s (prio %u handle %u)\n",
            opt->iface.ifname,
            opt->direction == TC_INGRESS ? "ingress" : "egress",
            opt->prio, opt->handle);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    static const struct prog_command cmds[] = {
        DEFINE_COMMAND(load, "Load a TC BPF program"),
        DEFINE_COMMAND(unload, "Unload a TC BPF program"),
        END_COMMANDS
    };

    return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                             sizeof(struct loadopt), PROG_NAME, false);
}
