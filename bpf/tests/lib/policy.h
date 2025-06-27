/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline void
policy_add_entry(bool egress, __u32 sec_label, __u8 protocol, __u16 dport, bool deny,
		 __u8 prefix_length)
{
	struct policy_key key = {
		.sec_label = sec_label,
		.egress = egress,
		.protocol = protocol,
		.dport = dport,
	};
	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = prefix_length,
	};

	map_update_elem(&cilium_policy_v2, &key, &value, BPF_ANY);
}

static __always_inline void
policy_add_ingress_allow_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(false, sec_label, protocol, dport, false, 0);
}

static __always_inline void
policy_add_l4_ingress_deny_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(false, sec_label, protocol, dport, true, LPM_PROTO_PREFIX_BITS);
}

static __always_inline void
policy_add_ingress_deny_all_entry(void)
{
	policy_add_entry(false, 0, 0, 0, true, 0);
}

static __always_inline void
policy_add_egress_allow_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(true, sec_label, protocol, dport, false, 0);
}

static __always_inline void policy_add_egress_allow_all_entry(void)
{
	policy_add_entry(true, 0, 0, 0, false, 0);
}

static __always_inline void policy_add_egress_deny_all_entry(void)
{
	policy_add_entry(true, 0, 0, 0, true, 0);
}

static __always_inline void policy_delete_egress_entry(void)
{
	struct policy_key key = {
		.egress = 1,
	};

	map_delete_elem(&cilium_policy_v2, &key);
}
