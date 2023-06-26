/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define CLIENT_PORT __bpf_htons(111)

enum egressgw_test {
	TEST_SNAT1                    = 0,
	TEST_SNAT2                    = 1,
	TEST_REDIRECT                 = 2,
	TEST_REDIRECT_SKIP_NO_GATEWAY = 3,
};

static __always_inline __be16 client_port(enum egressgw_test t)
{
	return CLIENT_PORT + (__be16)t;
}

static __always_inline void add_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr,
						      __be32 gateway_ip, __be32 egress_ip)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	struct egress_gw_policy_entry in_val = {
		.egress_ip  = egress_ip,
		.gateway_ip = gateway_ip,
	};

	map_update_elem(&EGRESS_POLICY_MAP, &in_key, &in_val, 0);
}

static __always_inline void del_egressgw_policy_entry(__be32 saddr, __be32 daddr, __u8 cidr)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr   = saddr,
		.daddr   = daddr,
	};

	map_delete_elem(&EGRESS_POLICY_MAP, &in_key);
}
