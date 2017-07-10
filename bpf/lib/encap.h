/*
 *  Copyright (C) 2016-2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __LIB_ENCAP_H_
#define __LIB_ENCAP_H_

#include "common.h"
#include "dbg.h"
#include "geneve.h"

/* validating options on tx is optional */
#undef VALIDATE_GENEVE_TX

#ifdef ENCAP_IFINDEX

static inline int __encap_and_redirect(struct __sk_buff *skb, struct endpoint_key *k,
				       __u32 seclabel, uint8_t *buf, int sz)
{
	struct endpoint_key *tunnel;
	struct bpf_tunnel_key key = {};
	__u32 node_id;
	int ret;

	if ((tunnel = map_lookup_elem(&tunnel_endpoint_map, k)) == NULL) {
		return DROP_NO_TUNNEL_ENDPOINT;
	}

	node_id = bpf_htonl(tunnel->ip4);
	key.tunnel_id = seclabel;
	key.remote_ipv4 = node_id;

	cilium_trace(skb, DBG_ENCAP, node_id, seclabel);

	ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

#ifdef GENEVE_OPTS
	ret = skb_set_tunnel_opt(skb, buf, sz);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
#ifdef VALIDATE_GENEVE_TX
	if (1) {
		struct geneveopt_val geneveopt_val = {};

		ret = parse_geneve_options(&geneveopt_val, buf);
		if (IS_ERR(ret))
			return ret;
	}
#endif /* VALIDATE_GENEVE_TX */
#endif /* GENEVE_OPTS */

	return redirect(ENCAP_IFINDEX, 0);
}

static inline int __inline__ encap_and_redirect(struct __sk_buff *skb, struct endpoint_key *key,
						__u32 seclabel)
{
#ifdef GENEVE_OPTS
	uint8_t buf[] = GENEVE_OPTS;
#else
	uint8_t buf[] = {};
#endif
	return __encap_and_redirect(skb, key, seclabel, buf, sizeof(buf));
}


#endif /* ENCAP_IFINDEX */

#endif /* __LIB_ENCAP_H_ */
