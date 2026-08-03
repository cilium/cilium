/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/ipv6.h>
#include "ipv6_core.h"

/* IPv4 option used to carry service addr and port for DSR.
 *
 * Copy = 1 (option is copied to each fragment)
 * Class = 0 (control option)
 * Number = 26 (not used according to [1])
 * Len = 8 (option type (1) + option len (1) + addr (4) + port (2))
 *
 * [1]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
 */
#define DSR_IPV4_OPT_TYPE	(IPOPT_COPY | 0x1a)

struct dsr_opt_v4 {
	__u8 type;
	__u8 len;
	__u16 port;
	__u32 addr;
};

/* IPv6 option type of Destination Option used to carry service IPv6 addr and
 * port for DSR.
 *
 * 0b00		- "skip over this option and continue processing the header"
 *     0	- "Option Data does not change en-route"
 *      11011   - Unassigned [1]
 *
 * [1]:  https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
 */
#define DSR_IPV6_OPT_TYPE	0x1B
#define DSR_IPV6_OPT_LEN	(sizeof(struct dsr_opt_v6) - 4)
#define DSR_IPV6_EXT_LEN	((sizeof(struct dsr_opt_v6) - 8) / 8)

/* The IPv6 extension should be 8-bytes aligned */
struct dsr_opt_v6 {
	struct ipv6_opt_hdr hdr;
	__u8 opt_type;
	__u8 opt_len;
	union v6addr addr;
	__be16 port;
	__u16 pad;
};
