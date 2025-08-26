/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_EGRESS_GATEWAY
static __always_inline void add_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr,
						      __be32 gateway_ip, __be32 egress_ip)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	struct egress_gw_policy_entry in_val = {
		.egress_ip  = egress_ip,
		.gateway_ip = gateway_ip,
	};

	map_update_elem(&cilium_egress_gw_policy_v4, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	map_delete_elem(&cilium_egress_gw_policy_v4, &in_key);
}

#ifdef ENABLE_IPV6
static __always_inline void add_egressgw_policy_entry_v6(const union v6addr *saddr,
							 const union v6addr *daddr,
							 __u8 cidr,
							 __be32 gateway_ip,
							 const union v6addr *egress_ip)
{
	struct egress_gw_policy_key6 in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V6(cidr), {} },
		.saddr   = *saddr,
		.daddr   = *daddr,
	};

	struct egress_gw_policy_entry6 in_val = {
		.egress_ip  = *egress_ip,
		.gateway_ip = gateway_ip,
	};

	map_update_elem(&cilium_egress_gw_policy_v6, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry_v6(const union v6addr *saddr,
							 const union v6addr *daddr,
							 __u8 cidr)
{
	struct egress_gw_policy_key6 in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V6(cidr), {} },
		.saddr   = *saddr,
		.daddr   = *daddr,
	};

	map_delete_elem(&cilium_egress_gw_policy_v6, &in_key);
}
#endif /* ENABLE_IPV6 */
#endif /* ENABLE_EGRESS_GATEWAY */
