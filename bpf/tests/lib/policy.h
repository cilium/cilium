/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline __u8
policy_calc_wildcard_bits(__u8 protocol, __u16 dport)
{
	__u8 wildcard_bits = 0;

	/* Wildcard the port: */
	if (!dport) {
		wildcard_bits += 16;

		/* Only wildcard protocol if port is also wildcarded: */
		if (!protocol)
			wildcard_bits += 8;
	}

	return wildcard_bits;
}

static __always_inline void
policy_delete_entry(bool egress, __u32 sec_label, __u8 protocol, __u16 dport)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(protocol, dport);
	/* Start with an exact L3/L4 policy, and wildcard it as determined above: */
	__u32 key_prefix_len = POLICY_FULL_PREFIX - wildcard_bits;

	struct policy_key key = {
		.lpm_key = { key_prefix_len, {} },
		.sec_label = sec_label,
		.egress = egress,
		.protocol = protocol,
		.dport = dport,
	};

	map_delete_elem(&cilium_policy_v2, &key);
}

static __always_inline void
policy_add_entry(bool egress, __u32 sec_label, __u8 protocol, __u16 dport, bool deny)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(protocol, dport);
	/* Start with an exact L3/L4 policy, and wildcard it as determined above: */
	__u32 key_prefix_len = POLICY_FULL_PREFIX - wildcard_bits;
	__u8 value_prefix_len = LPM_FULL_PREFIX_BITS - wildcard_bits;

	struct policy_key key = {
		.lpm_key = { key_prefix_len, {} },
		.sec_label = sec_label,
		.egress = egress,
		.protocol = protocol,
		.dport = dport,
	};
	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = value_prefix_len,
	};

	map_update_elem(&cilium_policy_v2, &key, &value, BPF_ANY);
}

static __always_inline void
policy_add_ingress_allow_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(false, sec_label, protocol, dport, false);
}

static __always_inline void
policy_add_l4_ingress_deny_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(false, sec_label, protocol, dport, true);
}

static __always_inline void
policy_add_ingress_deny_all_entry(void)
{
	policy_add_entry(false, 0, 0, 0, true);
}

static __always_inline void
policy_add_egress_allow_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(true, sec_label, protocol, dport, false);
}

static __always_inline void policy_add_egress_allow_all_entry(void)
{
	policy_add_entry(true, 0, 0, 0, false);
}

static __always_inline void policy_add_egress_deny_all_entry(void)
{
	policy_add_entry(true, 0, 0, 0, true);
}

static __always_inline void
policy_delete_egress_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_delete_entry(true, sec_label, protocol, dport);
}

static __always_inline void policy_delete_egress_all_entry(void)
{
	policy_delete_egress_entry(0, 0, 0);
}
