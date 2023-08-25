/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef SKIP_POLICY_MAP
static __always_inline void
policy_add_entry(bool egress, __u32 sec_label, __u8 protocol, __u16 dport, bool deny)
{
	struct policy_key key = {
		.sec_label = sec_label,
		.egress = egress,
		.protocol = protocol,
		.dport = dport,
	};
	struct policy_entry value = {
		.deny = deny,
	};

	map_update_elem(&POLICY_MAP, &key, &value, BPF_ANY);
}

static __always_inline void
policy_add_ingress_allow_entry(__u32 sec_label, __u8 protocol, __u16 dport)
{
	policy_add_entry(false, sec_label, protocol, dport, false);
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

static __always_inline void policy_delete_egress_entry(void)
{
	struct policy_key key = {
		.egress = 1,
	};

	map_delete_elem(&POLICY_MAP, &key);
}
#endif
