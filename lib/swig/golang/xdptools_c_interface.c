
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "xdptools_c_interface.h"

int xdpProgramAttach(struct xdp_program *xdp_prog,
			int ifindex, enum xdp_attach_mode mode,
			unsigned int flags) {
	return xdp_program__attach(xdp_prog, ifindex, mode, flags);
}

int xdpProgramDetach(struct xdp_program *xdp_prog,
			int ifindex, enum xdp_attach_mode mode,
			unsigned int flags) {
	return xdp_program__detach(xdp_prog, ifindex, mode, flags);
}
