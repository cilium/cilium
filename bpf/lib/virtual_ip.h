/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/lb.h"

#ifdef ENABLE_IPV4
/**
 * lookup_virtual_service_v4 - Look up a virtual service using wildcard entry
 * @dest_ip:	Destination IP address to look up
 *
 * Performs a wildcard lookup (port=0, proto=ANY) for a virtual service IP.
 * Tries both external and internal scopes to handle all service types.
 *
 * Returns pointer to lb4_service if found, NULL otherwise.
 */
static __always_inline struct lb4_service *
lookup_virtual_service_v4(__be32 dest_ip)
{
	struct lb4_key key = {
		.address = dest_ip,
		.dport = 0,
		.backend_slot = 0,
		.proto = IPPROTO_ANY,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb4_service *svc;

	/* First try external scope (where ClusterIP/LoadBalancer/NodePort services live) */
	svc = lb4_lookup_service(&key, false);
	if (!svc) {
		/* Then try internal scope (for dual-scope LoadBalancer/NodePort services) */
		key.scope = LB_LOOKUP_SCOPE_INT;
		svc = lb4_lookup_service(&key, false);
	}

	return svc;
}

/**
 * is_virtual_service_v4 - Check if an IP is a virtual service IP
 * @dest_ip:	Destination IP address to check
 *
 * Checks if the destination IP is a virtual service IP (ClusterIP or LoadBalancer)
 * by performing a wildcard lookup and checking if the service is non-routable.
 *
 * Returns true if the IP is a virtual service IP, false otherwise.
 */
static __always_inline bool
is_virtual_service_v4(__be32 dest_ip)
{
	struct lb4_service *svc = lookup_virtual_service_v4(dest_ip);
	return svc && !lb4_svc_is_routable(svc);
}

/**
 * lookup_virtual_service_v4_ext_only - Look up virtual service in external scope only
 * @dest_ip:	Destination IP address to look up
 *
 * Performs a wildcard lookup (port=0, proto=ANY) for a virtual service IP
 * in external scope only. This is used for compatibility with existing
 * drop traffic functionality that only checked external scope.
 *
 * Returns pointer to lb4_service if found, NULL otherwise.
 */
static __always_inline struct lb4_service *
lookup_virtual_service_v4_ext_only(__be32 dest_ip)
{
	struct lb4_key key = {
		.address = dest_ip,
		.dport = 0,
		.backend_slot = 0,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};

	lb4_key_set_protocol(&key, IPPROTO_ANY);
	return __lb4_lookup_service(&key);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/**
 * lookup_virtual_service_v6 - Look up a virtual service using wildcard entry
 * @dest_ip:	Destination IP address to look up
 *
 * Performs a wildcard lookup (port=0, proto=ANY) for a virtual service IP.
 * Tries both external and internal scopes to handle all service types.
 *
 * Returns pointer to lb6_service if found, NULL otherwise.
 */
static __always_inline struct lb6_service *
lookup_virtual_service_v6(const union v6addr *dest_ip)
{
	struct lb6_key key __align_stack_8 = {
		.dport = 0,
		.backend_slot = 0,
		.proto = IPPROTO_ANY,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	struct lb6_service *svc;

	ipv6_addr_copy(&key.address, dest_ip);

	/* First try external scope (where ClusterIP/LoadBalancer/NodePort services live) */
	svc = lb6_lookup_service(&key, false);
	if (!svc) {
		/* Then try internal scope (for dual-scope LoadBalancer/NodePort services) */
		key.scope = LB_LOOKUP_SCOPE_INT;
		svc = lb6_lookup_service(&key, false);
	}

	return svc;
}

/**
 * is_virtual_service_v6 - Check if an IP is a virtual service IP
 * @dest_ip:	Destination IP address to check
 *
 * Checks if the destination IP is a virtual service IP (ClusterIP or LoadBalancer)
 * by performing a wildcard lookup and checking if the service is non-routable.
 *
 * Returns true if the IP is a virtual service IP, false otherwise.
 */
static __always_inline bool
is_virtual_service_v6(const union v6addr *dest_ip)
{
	struct lb6_service *svc = lookup_virtual_service_v6(dest_ip);
	return svc && !lb6_svc_is_routable(svc);
}

/**
 * lookup_virtual_service_v6_ext_only - Look up virtual service in external scope only
 * @dest_ip:	Destination IP address to look up
 *
 * Performs a wildcard lookup (port=0, proto=ANY) for a virtual service IP
 * in external scope only. This is used for compatibility with existing
 * drop traffic functionality that only checked external scope.
 *
 * Returns pointer to lb6_service if found, NULL otherwise.
 */
static __always_inline struct lb6_service *
lookup_virtual_service_v6_ext_only(const union v6addr *dest_ip)
{
	struct lb6_key key = {};

	memcpy(&key.address, dest_ip, sizeof(key.address));
	key.dport = 0;
	key.scope = LB_LOOKUP_SCOPE_EXT;
	key.backend_slot = 0;
	lb6_key_set_protocol(&key, IPPROTO_ANY);

	return __lb6_lookup_service(&key);
}
#endif /* ENABLE_IPV6 */



