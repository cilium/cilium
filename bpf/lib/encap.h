/*
 *  Copyright (C) 2016-2018 Authors of Cilium
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

#ifdef ENCAP_IFINDEX
static inline int __inline__
encap_and_redirect_with_nodeid(struct __sk_buff *skb, __u32 tunnel_endpoint,
			       __u32 seclabel, __u32 monitor)
{
	struct bpf_tunnel_key key = {};
	__u32 node_id;
	int ret;

	node_id = bpf_htonl(tunnel_endpoint);
	key.tunnel_id = seclabel;
	key.remote_ipv4 = node_id;

	cilium_dbg(skb, DBG_ENCAP, node_id, seclabel);

	ret = skb_set_tunnel_key(skb, &key, sizeof(key), 0);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	send_trace_notify(skb, TRACE_TO_OVERLAY, seclabel, 0, 0, ENCAP_IFINDEX,
			  0, monitor);

	return redirect(ENCAP_IFINDEX, 0);
}

static inline int __inline__
encap_and_redirect(struct __sk_buff *skb, struct endpoint_key *k,
		   __u32 seclabel, __u32 monitor)
{
	struct endpoint_key *tunnel;

	if ((tunnel = map_lookup_elem(&TUNNEL_MAP, k)) == NULL) {
		return DROP_NO_TUNNEL_ENDPOINT;
	}

	return encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
}
#endif /* ENCAP_IFINDEX */
#endif /* __LIB_ENCAP_H_ */
