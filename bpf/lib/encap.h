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
#ifdef ENABLE_IPSEC
static inline int __inline__
enacap_and_redirect_nomark_ipsec(struct __sk_buff *skb, __u32 tunnel_endpoint, __u8 key,
			 __u32 seclabel)
{
	/* Traffic from local host in tunnel mode will be passed to
	 * cilium_host. In non-IPSec case traffic with non-local dst
	 * will then be redirected to tunnel device. In IPSec case
	 * though we need to traverse xfrm path still. The mark +
	 * cb[4] hints will not survive a veth pair xmit to ingress
	 * however so below encap_and_redirect_ipsec will not work.
	 * Instead pass hints via cb[0], cb[4] (cb is not cleared
	 * by dev_skb_forward) and catch hints with bpf_ipsec prog
	 * that will populate mark/cb as expected by xfrm and 2nd
	 * traversal into bpf_netdev. Remember we can't use cb[0-3]
	 * in both cases because xfrm layer would overwrite them. We
	 * use cb[4] here so it doesn't need to be reset by bpf_ipsec.
	 */
	skb->cb[0] = or_encrypt_key(key);
	skb->cb[1] = seclabel;
	skb->cb[4] = tunnel_endpoint;
	return IPSEC_ENDPOINT;
}

static inline int __inline__
encap_and_redirect_ipsec(struct __sk_buff *skb, __u32 tunnel_endpoint, __u8 key,
			 __u32 seclabel)
{
	/* IPSec is performed by the stack on any packets with the
	 * MARK_MAGIC_ENCRYPT bit set. During the process though we
	 * lose the lxc context (seclabel and tunnel endpoint). The
	 * tunnel endpoint can be looked up from daddr but the sec
	 * label is stashed in the mark and extracted in bpf_netdev
	 * to send skb onto tunnel for encap.
	 */
	set_encrypt_key(skb, key);
	set_identity(skb, seclabel);
	skb->cb[4] = tunnel_endpoint;
	return IPSEC_ENDPOINT;
}
#endif

static inline int __inline__
__encap_with_nodeid(struct __sk_buff *skb, __u32 tunnel_endpoint,
		    __u32 seclabel, __u32 monitor)
{
	struct bpf_tunnel_key key = {};
	__u32 node_id;
	int ret;

	node_id = bpf_htonl(tunnel_endpoint);
	key.tunnel_id = seclabel;
	key.remote_ipv4 = node_id;

	cilium_dbg(skb, DBG_ENCAP, node_id, seclabel);

	ret = skb_set_tunnel_key(skb, &key, sizeof(key), BPF_F_ZERO_CSUM_TX);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	send_trace_notify(skb, TRACE_TO_OVERLAY, seclabel, 0, 0, ENCAP_IFINDEX,
			  0, monitor);
	return 0;
}

static inline int __inline__
__encap_and_redirect_with_nodeid(struct __sk_buff *skb, __u32 tunnel_endpoint,
				 __u32 seclabel, __u32 monitor)
{
	int ret = __encap_with_nodeid(skb, tunnel_endpoint, seclabel, monitor);
	if (ret != 0)
		return ret;
	return redirect(ENCAP_IFINDEX, 0);
}

/* encap_and_redirect_with_nodeid returns IPSEC_ENDPOINT after skb meta-data is
 * set when IPSec is enabled. Caller should pass the skb to the stack at this
 * point. Otherwise returns TC_ACT_REDIRECT on successful redirect to tunnel
 * device. On error returns TC_ACT_SHOT, DROP_NO_TUNNEL_ENDPOINT or
 * DROP_WRITE_ERROR.
 */
static inline int __inline__
encap_and_redirect_with_nodeid(struct __sk_buff *skb, __u32 tunnel_endpoint,
			       __u8 key, __u32 seclabel, __u32 monitor)
{
#ifdef ENABLE_IPSEC
	if (key)
		return enacap_and_redirect_nomark_ipsec(skb, tunnel_endpoint, key, seclabel);
#endif
	return __encap_and_redirect_with_nodeid(skb, tunnel_endpoint, seclabel, monitor);
}

/* encap_and_redirect based on ENABLE_IPSEC flag and from_host bool will decide
 * which version of code to call. With IPSec enabled and from_host set use the
 * IPSec branch which configures metadata for IPSec kernel stack. Otherwise
 * packet is redirected to output tunnel device and skb will not be seen by
 * IP stack.
 *
 * Returns IPSEC_ENDPOINT when skb needs to be handed to IP stack for IPSec
 * handling, TC_ACT_SHOT, DROP_NO_TUNNEL_ENDPOINT or DROP_WRITE_ERROR on error,
 * and finally on successful redirect returns TC_ACT_REDIRECT.
 */
static inline int __inline__
encap_and_redirect_lxc(struct __sk_buff *skb, __u32 tunnel_endpoint, __u8 encrypt_key, struct endpoint_key *key, __u32 seclabel, __u32 monitor)
{
	struct endpoint_key *tunnel;

	if (tunnel_endpoint) {
#ifdef ENABLE_IPSEC
		if (encrypt_key)
			return encap_and_redirect_ipsec(skb, tunnel_endpoint, encrypt_key, seclabel);
#endif
		return __encap_and_redirect_with_nodeid(skb, tunnel_endpoint, seclabel, monitor);
	}

	if ((tunnel = map_lookup_elem(&TUNNEL_MAP, key)) == NULL) {
		return DROP_NO_TUNNEL_ENDPOINT;
	}

#ifdef ENABLE_IPSEC
	if (tunnel->key) {
		__u8 min_encrypt_key = get_min_encrypt_key(tunnel->key);

		return encap_and_redirect_ipsec(skb, tunnel->ip4,
						min_encrypt_key,
						seclabel);
	}
#endif
	return __encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
}

static inline int __inline__
encap_and_redirect_netdev(struct __sk_buff *skb, struct endpoint_key *k, __u32 seclabel, __u32 monitor)
{
	struct endpoint_key *tunnel;

	if ((tunnel = map_lookup_elem(&TUNNEL_MAP, k)) == NULL) {
		return DROP_NO_TUNNEL_ENDPOINT;
	}

#ifdef ENABLE_IPSEC
	if (tunnel->key) {
		__u8 key = get_min_encrypt_key(tunnel->key);

		return enacap_and_redirect_nomark_ipsec(skb, tunnel->ip4,
						       key, seclabel);
	}
#endif
	return __encap_and_redirect_with_nodeid(skb, tunnel->ip4, seclabel, monitor);
}
#endif /* ENCAP_IFINDEX */
#endif /* __LIB_ENCAP_H_ */
