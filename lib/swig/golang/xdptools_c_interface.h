#ifndef __XDPTOOLS_C_INTERFACE_H__
#define __XDPTOOLS_C_INTERFACE_H__
#include <xdp/libxdp.h>

int xdpProgramAttach(struct xdp_program *, int , enum xdp_attach_mode ,unsigned int);

int xdpProgramDetach(struct xdp_program *, int , enum xdp_attach_mode ,unsigned int);


#endif
