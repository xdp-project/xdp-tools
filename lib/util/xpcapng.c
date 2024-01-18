// SPDX-License-Identifier: GPL-2.0
/*
 *  Description:
 *      Simple PcapNG library developed from scratch as no library existed that
 *      met the requirements for xdpdump. It can also be used by other XDP
 *      applications that would like to capture packets for debugging purposes.
 */

/*****************************************************************************
 * Include files
 *****************************************************************************/
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/uio.h>

#include "xpcapng.h"

/*****************************************************************************
 * Simple roundup() macro
 *****************************************************************************/
#ifndef roundup
#define roundup(x, y) (                  \
{                                        \
	typeof(y) __y = y;               \
	(((x) + (__y - 1)) / __y) * __y; \
}                                        \
)
#endif

/*****************************************************************************
 * pcapng_dumper structure
 *****************************************************************************/
struct xpcapng_dumper {
	int      pd_fd;
	uint32_t pd_interfaces;
};

/*****************************************************************************
 * general pcapng block and option definitions
 *****************************************************************************/
enum pcapng_block_types {
	PCAPNG_SECTION_BLOCK = 0x0A0D0D0A,
	PCAPNG_INTERFACE_BLOCK = 1,
	PCAPNG_PACKET_BLOCK,
	PCAPNG_SIMPLE_PACKET_BLOCK,
	PCAPNG_NAME_RESOLUTION_BLOCK,
	PCAPNG_INTERFACE_STATS_BLOCK,
	PCAPNG_ENHANCED_PACKET_BLOCK
};

struct pcapng_option {
	uint16_t po_type;
	uint16_t po_length;
	uint8_t  po_data[];
} __attribute__((__packed__));

enum pcapng_opt {
	PCAPNG_OPT_END	= 0,
	PCAPNG_OPT_COMMENT = 1,
	PCAPNG_OPT_CUSTOME_2988 = 2988,
	PCAPNG_OPT_CUSTOME_2989 = 2989,
	PCAPNG_OPT_CUSTOME_19372 = 19372,
	PCAPNG_OPT_CUSTOME_19373 = 29373
};

/*****************************************************************************
 * pcapng section header block definitions
 *****************************************************************************/
struct pcapng_section_header_block {
	uint32_t shb_block_type;
	uint32_t shb_block_length;
	uint32_t shb_byte_order_magic;
	uint16_t shb_major_version;
	uint16_t shb_minor_version;
	uint64_t shb_section_length;
	uint8_t  shb_options[];
	/* The options are followed by another:
	 *   uint32_t shb_block_length;
	 */
} __attribute__((__packed__));

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D
#define PCAPNG_MAJOR_VERSION    1
#define PCAPNG_MINOR_VERSION    0

enum pcapng_opt_shb {
	PCAPNG_OPT_SHB_HARDWARE = 2,
	PCAPNG_OPT_SHB_OS,
	PCAPNG_OPT_SHB_USERAPPL
};

/*****************************************************************************
 * pcapng interface description block definitions
 *****************************************************************************/
struct pcapng_interface_description_block {
	uint32_t idb_block_type;
	uint32_t idb_block_length;
	uint16_t idb_link_type;
	uint16_t idb_reserved;
	uint32_t idb_snap_len;
	uint8_t  idb_options[];
	/* The options are followed by another:
	 *   uint32_t idb_block_length;
	 */
} __attribute__((__packed__));

enum pcapng_opt_idb {
	PCAPNG_OPT_IDB_IF_NAME = 2,
	PCAPNG_OPT_IDB_IF_DESCRIPTION,
	PCAPNG_OPT_IDB_IF_IPV4_ADDR,
	PCAPNG_OPT_IDB_IF_IPV6_ADDR,
	PCAPNG_OPT_IDB_IF_MAC_ADDR,
	PCAPNG_OPT_IDB_IF_EUI_ADDR,
	PCAPNG_OPT_IDB_IF_SPEED,
	PCAPNG_OPT_IDB_IF_TSRESOL,
	PCAPNG_OPT_IDB_IF_TZONE,
	PCAPNG_OPT_IDB_IF_FILTER,
	PCAPNG_OPT_IDB_IF_OS,
	PCAPNG_OPT_IDB_IF_FCSLEN,
	PCAPNG_OPT_IDB_IF_TOFFSET,
	PCAPNG_OPT_IDB_IF_HARDWARE
};

/*****************************************************************************
 * pcapng interface description block definitions
 *****************************************************************************/
struct pcapng_enhanced_packet_block {
	uint32_t epb_block_type;
	uint32_t epb_block_length;
	uint32_t epb_interface_id;
	uint32_t epb_timestamp_hi;
	uint32_t epb_timestamp_low;
	uint32_t epb_captured_length;
	uint32_t epb_original_length;
	uint8_t  epb_packet_data[];
	/* The packet data is followed by:
	 *   uint8_t  epb_options[];
	 *   uint32_t epb_block_length;
	 */
} __attribute__((__packed__));

enum pcapng_opt_epb {
	PCAPNG_OPT_EPB_FLAGS = 2,
	PCAPNG_OPT_EPB_HASH,
	PCAPNG_OPT_EPB_DROPCOUNT,
	PCAPNG_OPT_EPB_PACKETID,
	PCAPNG_OPT_EPB_QUEUE,
	PCAPNG_OPT_EPB_VERDICT
};

enum pcapng_epb_vedict_type {
	PCAPNG_EPB_VEDRICT_TYPE_HARDWARE = 0,
	PCAPNG_EPB_VEDRICT_TYPE_EBPF_TC,
	PCAPNG_EPB_VEDRICT_TYPE_EBPF_XDP
};

/*****************************************************************************
 * pcapng_get_option_length()
 *****************************************************************************/
static size_t pcapng_get_option_length(size_t len)
{
	return roundup(sizeof(struct pcapng_option) + len, sizeof(uint32_t));
}

/*****************************************************************************
 * pcapng_add_option()
 *****************************************************************************/
static struct pcapng_option *pcapng_add_option(struct pcapng_option *opt,
					       uint16_t type, uint16_t length,
					       const void *data)
{
	if (opt == NULL)
		return NULL;

	opt->po_type = type;
	opt->po_length = length;
	if (data)
		memcpy(opt->po_data, data, length);

	return (struct pcapng_option *)
		((uint8_t *)opt + pcapng_get_option_length(length));
}

/*****************************************************************************
 * pcapng_write_shb()
 *****************************************************************************/
static bool pcapng_write_shb(struct xpcapng_dumper *pd, const char *comment,
			     const char *hardware, const char *os,
			     const char *user_application)
{
	int                                 rc;
	size_t                              shb_length;
	struct pcapng_section_header_block *shb;
	struct pcapng_option               *opt;

	if (pd == NULL) {
		errno = EINVAL;
		return false;
	}

	/* First calculate the total length of the SHB. */
	shb_length = sizeof(*shb);

	if (comment)
		shb_length += pcapng_get_option_length(strlen(comment));

	if (hardware)
		shb_length += pcapng_get_option_length(strlen(hardware));

	if (os)
		shb_length += pcapng_get_option_length(strlen(os));

	if (user_application)
		shb_length += pcapng_get_option_length(
			strlen(user_application));

	shb_length += pcapng_get_option_length(0);
	shb_length += sizeof(uint32_t);

	/* Allocate the SHB and fill it. */
	shb = calloc(1, shb_length);
	if (shb == NULL) {
		errno = ENOMEM;
		return false;
	}

	shb->shb_block_type = PCAPNG_SECTION_BLOCK;
	shb->shb_block_length = shb_length;
	shb->shb_byte_order_magic = PCAPNG_BYTE_ORDER_MAGIC;
	shb->shb_major_version = PCAPNG_MAJOR_VERSION;
	shb->shb_minor_version = PCAPNG_MINOR_VERSION;
	shb->shb_section_length = UINT64_MAX;

	/* Add the options and block_length value */
	opt = (struct pcapng_option *) &shb->shb_options;

	if (comment)
		opt = pcapng_add_option(opt, PCAPNG_OPT_COMMENT,
					strlen(comment), comment);

	if (hardware)
		opt = pcapng_add_option(opt, PCAPNG_OPT_SHB_HARDWARE,
					strlen(hardware), hardware);

	if (os)
		opt = pcapng_add_option(opt, PCAPNG_OPT_SHB_OS,
					strlen(os), os);

	if (user_application)
		opt = pcapng_add_option(opt, PCAPNG_OPT_SHB_USERAPPL,
					strlen(user_application),
					user_application);
	/* WARNING: If a new option is added, make sure the length calculation
	 *          above is also updated!
	 */

	opt = pcapng_add_option(opt, PCAPNG_OPT_END, 0, NULL);
	memcpy(opt, &shb->shb_block_length, sizeof(shb->shb_block_length));

	/* Write the SHB, and free its memory. */
	rc = write(pd->pd_fd, shb, shb_length);
	free(shb);

	if ((size_t)rc != shb_length)
		return false;

	return true;
}

/*****************************************************************************
 * pcapng_write_idb()
 *****************************************************************************/
static bool pcapng_write_idb(struct xpcapng_dumper *pd, const char *name,
			     uint16_t snap_len, const char *description,
			     const uint8_t *mac, uint64_t speed,
			     uint8_t ts_resolution, const char *hardware)
{
	int                                        rc;
	size_t                                     idb_length;
	struct pcapng_interface_description_block *idb;
	struct pcapng_option                      *opt;

	if (pd == NULL) {
		errno = EINVAL;
		return false;
	}

	/* First calculate the total length of the IDB. */
	idb_length = sizeof(*idb);

	if (name)
		idb_length += pcapng_get_option_length(strlen(name));

	if (description)
		idb_length += pcapng_get_option_length(strlen(description));

	if (mac)
		idb_length += pcapng_get_option_length(6);

	if (speed)
		idb_length += pcapng_get_option_length(sizeof(uint64_t));

	if (ts_resolution != 6 && ts_resolution != 0)
		idb_length += pcapng_get_option_length(1);

	if (hardware)
		idb_length += pcapng_get_option_length(strlen(hardware));

	idb_length += pcapng_get_option_length(0);
	idb_length += sizeof(uint32_t);

	/* Allocate the IDB and fill it. */
	idb = calloc(1, idb_length);
	if (idb == NULL) {
		errno = ENOMEM;
		return false;
	}

	idb->idb_block_type = PCAPNG_INTERFACE_BLOCK;
	idb->idb_block_length = idb_length;
	idb->idb_link_type = 1; /* Ethernet */
	idb->idb_snap_len = snap_len;

	/* Add the options and block_length value */
	opt = (struct pcapng_option *) &idb->idb_options;

	if (name)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_NAME,
					strlen(name), name);

	if (description)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_DESCRIPTION,
					strlen(description), description);

	if (mac)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_MAC_ADDR, 6,
					mac);

	if (speed)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_SPEED,
					sizeof(uint64_t), &speed);

	if (ts_resolution != 6 && ts_resolution != 0)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_TSRESOL,
					sizeof(uint8_t), &ts_resolution);

	if (hardware)
		opt = pcapng_add_option(opt, PCAPNG_OPT_IDB_IF_HARDWARE,
					strlen(hardware), hardware);
	/* WARNING: If a new option is added, make sure the length calculation
	 *          above is also updated!
	 */

	opt = pcapng_add_option(opt, PCAPNG_OPT_END, 0, NULL);
	memcpy(opt, &idb->idb_block_length, sizeof(idb->idb_block_length));

	/* Write the IDB, and free it's memory. */
	rc = write(pd->pd_fd, idb, idb_length);
	free(idb);

	if ((size_t)rc != idb_length)
		return false;

	return true;
}

/*****************************************************************************
 * pcapng_write_epb()
 *****************************************************************************/
static bool pcapng_write_epb(struct xpcapng_dumper *pd, uint32_t ifid,
			     const uint8_t *pkt, uint32_t len,
			     uint32_t caplen, uint64_t timestamp,
			     struct xpcapng_epb_options_s *epb_options)
{
	int                                  i = 0;
	int                                  rc;
	size_t                               pad_length;
	size_t                               com_length = 0;
	size_t                               epb_length;
	struct pcapng_enhanced_packet_block  epb;
	struct pcapng_option                *opt;
	struct iovec                         iov[7];
	static uint8_t                       pad[4] = {0, 0, 0, 0};
	uint8_t                              options[8 + 12 + 12 + 8 + 16 + 4 + 4];
					     /* PCAPNG_OPT_EPB_FLAGS[8] +
					      * PCAPNG_OPT_EPB_DROPCOUNT[12] +
					      * PCAPNG_OPT_EPB_PACKETID[12] +
					      * PCAPNG_OPT_EPB_QUEUE[8] +
					      * PCAPNG_OPT_EPB_VERDICT[16] +
					      * PCAPNG_OPT_END[4] +
					      * epb_block_length
					      */
	static struct xdp_verdict {
		uint8_t type;
		int64_t verdict;
	}__attribute__((__packed__)) verdict = {
		PCAPNG_EPB_VEDRICT_TYPE_EBPF_XDP, 0 };

	if (pd == NULL) {
		errno = EINVAL;
		return false;
	}

	/* First calculate the total length of the EPB. */
	pad_length = roundup(caplen, sizeof(uint32_t)) - caplen;

	epb_length = sizeof(epb);
	epb_length += caplen + pad_length;

	if (epb_options->flags)
		epb_length += pcapng_get_option_length(sizeof(uint32_t));

	if (epb_options->dropcount)
		epb_length += pcapng_get_option_length(sizeof(uint64_t));

	if (epb_options->packetid)
		epb_length += pcapng_get_option_length(sizeof(uint64_t));

	if (epb_options->queue)
		epb_length += pcapng_get_option_length(sizeof(uint32_t));

	if (epb_options->xdp_verdict)
		epb_length += pcapng_get_option_length(sizeof(verdict));

	if (epb_options->comment) {
		com_length = strlen(epb_options->comment);
		epb_length += pcapng_get_option_length(com_length);
	}

	epb_length += pcapng_get_option_length(0);
	epb_length += sizeof(uint32_t);

	/* Fill in the EPB. */
	epb.epb_block_type = PCAPNG_ENHANCED_PACKET_BLOCK;
	epb.epb_block_length = epb_length;
	epb.epb_interface_id = ifid;
	epb.epb_timestamp_hi = timestamp >> 32;
	epb.epb_timestamp_low = (uint32_t) timestamp;
	epb.epb_captured_length = caplen;
	epb.epb_original_length = len;

	/* Add the flag/end option and block_length value */
	opt = (struct pcapng_option *) options;

	if (epb_options->flags)
		opt = pcapng_add_option(opt, PCAPNG_OPT_EPB_FLAGS,
					sizeof(uint32_t), &epb_options->flags);

	if (epb_options->dropcount)
		opt = pcapng_add_option(opt, PCAPNG_OPT_EPB_DROPCOUNT,
					sizeof(uint64_t),
					&epb_options->dropcount);

	if (epb_options->packetid)
		opt = pcapng_add_option(opt, PCAPNG_OPT_EPB_PACKETID,
					sizeof(uint64_t),
					epb_options->packetid);

	if (epb_options->queue)
		opt = pcapng_add_option(opt, PCAPNG_OPT_EPB_QUEUE,
					sizeof(uint32_t), epb_options->queue);

	if (epb_options->xdp_verdict) {
		verdict.verdict = *epb_options->xdp_verdict;
		opt = pcapng_add_option(opt, PCAPNG_OPT_EPB_VERDICT,
					sizeof(verdict), &verdict);
	}
	/* WARNING: If a new option is added, make sure the length calculation
	 *          and the options[] variable above are also updated!
	 */

	opt = pcapng_add_option(opt, PCAPNG_OPT_END, 0, NULL);
	memcpy(opt, &epb.epb_block_length, sizeof(epb.epb_block_length));

	/* Write the EPB in parts, including the options, this looks not as
	 * straightforward as pcapng_write_idb() but here we would like to
	 * avoid as many memcopy's as possible.
	 */

	/* Add base EPB structure. */
	iov[i].iov_base = &epb;
	iov[i++].iov_len = sizeof(epb);

	/* Add Packet Data. */
	iov[i].iov_base = (void *)pkt;
	iov[i++].iov_len = caplen;

	/* Add Packet Data padding if needed. */
	if (pad_length > 0) {
		iov[i].iov_base = pad;
		iov[i++].iov_len = pad_length;
	}

	/* Add comment if supplied */
	if (epb_options->comment) {
		uint16_t opt[2] = {PCAPNG_OPT_COMMENT, com_length};
		size_t   opt_pad = roundup(com_length,
					   sizeof(uint32_t)) - com_length;
		/* Add option header. */
		iov[i].iov_base = opt;
		iov[i++].iov_len = sizeof(opt);

		/* Add actual comment string. */
		iov[i].iov_base = (void *)epb_options->comment;
		iov[i++].iov_len = com_length;

		/* Add padding to uint32_t if needed. */
		if (opt_pad) {
			iov[i].iov_base = pad;
			iov[i++].iov_len = opt_pad;
		}
	}

	/* Write other options and final EPB size. */
	iov[i].iov_base = options;
	iov[i++].iov_len = 8 + (epb_options->flags ? 8 : 0) +
		(epb_options->dropcount ? 12 : 0) +
		(epb_options->packetid ? 12 : 0) +
		(epb_options->queue ? 8 : 0) +
		(epb_options->xdp_verdict ? 16 : 0);
	rc = writev(pd->pd_fd, iov, i);
	if ((size_t)rc != epb_length)
		return false;

	return true;
}

/*****************************************************************************
 * xpcapng_dump_open()
 *****************************************************************************/
struct xpcapng_dumper *xpcapng_dump_open(const char *file,
					 const char *comment,
					 const char *hardware,
					 const char *os,
					 const char *user_application)
{
	struct xpcapng_dumper *pd = NULL;

	if (file == NULL) {
		errno = EINVAL;
		goto error_exit;
	}

	pd = calloc(1, sizeof(*pd));
	if (pd == NULL) {
		errno = ENOMEM;
		goto error_exit;
	}
	pd->pd_fd = -1;

	if (strcmp(file, "-") == 0) {
		pd->pd_fd = STDOUT_FILENO;
	} else {
		pd->pd_fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (pd->pd_fd < 0)
			goto error_exit;
	}

	if (!pcapng_write_shb(pd, comment, hardware, os, user_application))
		goto error_exit;

	return pd;

error_exit:
	if (pd) {
		if (pd->pd_fd >= 0 && pd->pd_fd != STDOUT_FILENO)
			close(pd->pd_fd);

		free(pd);
	}
	return NULL;
}

/*****************************************************************************
 * xpcapng_dump_close()
 *****************************************************************************/
void xpcapng_dump_close(struct xpcapng_dumper *pd)
{
	if (pd == NULL)
		return;

	if (pd->pd_fd < 0 && pd->pd_fd != STDOUT_FILENO)
		close(pd->pd_fd);

	free(pd);
}

/*****************************************************************************
 * xpcapng_dump_flush()
 *****************************************************************************/
int xpcapng_dump_flush(struct xpcapng_dumper *pd)
{
	if (pd != NULL)
		return fsync(pd->pd_fd);

	errno = EINVAL;
	return -1;
}

/*****************************************************************************
 * pcapng_dump_add_interface()
 *****************************************************************************/
int xpcapng_dump_add_interface(struct xpcapng_dumper *pd, uint16_t snap_len,
			       const char *name, const char *description,
			       const uint8_t *mac, uint64_t speed,
			       uint8_t ts_resolution, const char *hardware)
{
	if (!pcapng_write_idb(pd, name, snap_len, description, mac, speed,
			      ts_resolution, hardware))
		return -1;

	return pd->pd_interfaces++;
}

/*****************************************************************************
 * xpcapng_dump_enhanced_pkt()
 *****************************************************************************/
bool xpcapng_dump_enhanced_pkt(struct xpcapng_dumper *pd, uint32_t ifid,
			       const uint8_t *pkt, uint32_t len,
			       uint32_t caplen, uint64_t timestamp,
			       struct xpcapng_epb_options_s *options)
{
	struct xpcapng_epb_options_s default_options = {};

	return pcapng_write_epb(pd, ifid, pkt, len, caplen, timestamp,
				options ?: &default_options);
}
