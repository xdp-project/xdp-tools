/* SPDX-License-Identifier: GPL-2.0 */

/*****************************************************************************
 * Multiple include protection
 *****************************************************************************/
#ifndef __XPCAPNG_H_
#define __XPCAPNG_H_

/*****************************************************************************
 * Handle
 *****************************************************************************/
struct xpcapng_dumper;

/*****************************************************************************
 * Flag variables
 *****************************************************************************/
enum xpcapng_epb_flags {
	PCAPNG_EPB_FLAG_INBOUND  = 0x1,
	PCAPNG_EPB_FLAG_OUTBOUND = 0x2
};

/*****************************************************************************
 * EPB options structure
 *****************************************************************************/
struct xpcapng_epb_options_s {
	enum xpcapng_epb_flags  flags;
	uint64_t                dropcount;
	uint64_t               *packetid;
	uint32_t               *queue;
	int64_t                *xdp_verdict;
	const char             *comment;
};

/*****************************************************************************
 * APIs
 *****************************************************************************/
extern struct xpcapng_dumper *xpcapng_dump_open(const char *file,
						const char *comment,
						const char *hardware,
						const char *os,
						const char *user_application);
extern void xpcapng_dump_close(struct xpcapng_dumper *pd);
extern int xpcapng_dump_flush(struct xpcapng_dumper *pd);
extern int xpcapng_dump_add_interface(struct xpcapng_dumper *pd,
				      uint16_t snap_len,
				      const char *name, const char *description,
				      const uint8_t *mac, uint64_t speed,
				      uint8_t ts_resolution,
				      const char *hardware);
extern bool xpcapng_dump_enhanced_pkt(struct xpcapng_dumper *pd, uint32_t ifid,
				      const uint8_t *pkt, uint32_t len,
				      uint32_t caplen, uint64_t timestamp,
				      struct xpcapng_epb_options_s *options);

/*****************************************************************************
 * End-of include file
 *****************************************************************************/
#endif /* __XPCAPNG_H_ */
