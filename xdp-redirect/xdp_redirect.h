// SPDX-License-Identifier: GPL-2.0-only
#ifndef XDP_REDIRECT_H
#define XDP_REDIRECT_H

int xdp_redirect_basic_main(int argc, char *argv[]);
int xdp_redirect_cpumap_main(int argc, char *argv[]);
int xdp_redirect_devmap_main(int argc, char *argv[]);
int xdp_redirect_devmap_multi_main(int argc, char *argv[]);

#endif
