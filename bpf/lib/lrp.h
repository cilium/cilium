/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

struct skip_lb4_key {
	__u64 netns_cookie;     /* Source pod netns cookie */
	__u32 address;          /* Destination service virtual IPv4 address */
	__u16 port;             /* Destination service virtual layer4 port */
	__u16 pad;
};

struct skip_lb6_key {
	__u64 netns_cookie;     /* Source pod netns cookie */
	union v6addr address;   /* Destination service virtual IPv6 address */
	__u32 pad;
	__u16 port;             /* Destination service virtual layer4 port */
	__u16 pad2;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct skip_lb6_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SKIP_MAP_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_skip_lb6 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct skip_lb4_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SKIP_MAP_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_skip_lb4 __section_maps_btf;

DECLARE_CONFIG(bool, enable_lrp, "Enable support for Local Redirect Policy")

static __always_inline bool
lrp_v6_skip_xlate_from_ctx_to_svc(__net_cookie cookie, union v6addr addr, __be16 port)
{
	struct skip_lb6_key key;
	__u8 *val = NULL;

	memset(&key, 0, sizeof(key));
	key.netns_cookie = cookie;
	key.address = addr;
	key.port = port;
	val = map_lookup_elem(&cilium_skip_lb6, &key);
	if (val)
		return true;
	return false;
}

/* Service translation logic for a local-redirect service can cause packets to
 * be looped back to a service node-local backend after translation. This can
 * happen when the node-local backend itself tries to connect to the service
 * frontend for which it acts as a backend. There are cases where this can break
 * traffic flow if the backend needs to forward the redirected traffic to the
 * actual service frontend. Hence, allow service translation for pod traffic
 * getting redirected to backend (across network namespaces), but skip service
 * translation for backend to itself or another service backend within the same
 * namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
 *
 * For example, in EKS cluster, a local-redirect service exists with the AWS
 * metadata IP, port as the frontend <169.254.169.254, 80> and the proxy as a
 * backend Pod. When traffic destined to the frontend originates from the
 * Pod in namespace ns1 (host ns when the proxy Pod is deployed in
 * hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
 * traffic would get looped back to the proxy Pod.
 */
static __always_inline bool
lrp_v4_skip_xlate_from_ctx_to_svc(__net_cookie cookie, __be32 address, __be16 port)
{
	struct skip_lb4_key key;
	__u8 *val = NULL;

	memset(&key, 0, sizeof(key));
	key.netns_cookie = cookie;
	key.address = address;
	key.port = port;
	val = map_lookup_elem(&cilium_skip_lb4, &key);
	if (val)
		return true;
	return false;
}
