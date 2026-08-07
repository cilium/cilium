/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

static __always_inline __u8
policy_calc_wildcard_bits(__u8 protocol, __be16 dport, __u8 port_range)
{
	__u8 wildcard_bits = 0;

	/* Partially wildcard the port: */
	if (dport && port_range) {
		wildcard_bits = port_range;
	/* Fully wildcard the port: */
	} else if (!dport) {
		wildcard_bits += 16;

		/* Only wildcard protocol if port is also wildcarded: */
		if (!protocol)
			wildcard_bits += 8;
	}

	return wildcard_bits;
}

static __always_inline void
policy_delete_entry(bool egress, __u32 sec_label, __u8 protocol, __be16 dport,
		    __u8 port_range)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(protocol, dport, port_range);
	/* Start with an exact L3/L4 policy, and wildcard it as determined above: */
	__u32 key_prefix_len = POLICY_FULL_PREFIX - wildcard_bits;

	struct policy_key key = {
		.lpm_key = { key_prefix_len, {} },
		.sec_label = sec_label,
		.egress = egress,
		.protocol = protocol,
		.dport = dport,
	};

	map_delete_elem(&cilium_policy, &key);
}

static __always_inline void
policy_add_entry(bool egress, __u32 sec_label, __u8 protocol, __be16 dport,
		 __u8 port_range, bool deny, __be16 proxy_port)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(protocol, dport, port_range);
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
		.proxy_port = proxy_port,
	};

	map_update_elem(&cilium_policy, &key, &value, BPF_ANY);
}

static __always_inline void
policy_add_ingress_allow_l3_l4_entry(__u32 sec_label, __u8 protocol, __be16 dport,
				     __u8 port_range)
{
	policy_add_entry(false, sec_label, protocol, dport, port_range, false, 0);
}

static __always_inline void
policy_add_ingress_deny_l4_entry(__u8 protocol, __be16 dport, __u8 port_range)
{
	policy_add_entry(false, 0, protocol, dport, port_range, true, 0);
}

static __always_inline void
policy_add_ingress_deny_all_entry(void)
{
	policy_add_entry(false, 0, 0, 0, 0, true, 0);
}

static __always_inline void policy_add_ingress_allow_all_entry(void)
{
	policy_add_entry(false, 0, 0, 0, 0, false, 0);
}

static __always_inline void
policy_delete_ingress_l3_l4_entry(__u32 sec_label, __u8 protocol, __be16 dport,
				  __u8 port_range)
{
	policy_delete_entry(false, sec_label, protocol, dport, port_range);
}

static __always_inline void policy_delete_ingress_all_entry(void)
{
	policy_delete_ingress_l3_l4_entry(0, 0, 0, 0);
}

static __always_inline void
policy_add_egress_allow_l3_l4_entry(__u32 sec_label, __u8 protocol, __be16 dport,
				    __u8 port_range)
{
	policy_add_entry(true, sec_label, protocol, dport, port_range, false, 0);
}

static __always_inline void
policy_add_egress_allow_l3_entry(__u32 sec_label)
{
	policy_add_egress_allow_l3_l4_entry(sec_label, 0, 0, 0);
}

static __always_inline void
policy_add_egress_allow_l4_entry(__u8 protocol, __be16 dport, __u8 port_range)
{
	policy_add_egress_allow_l3_l4_entry(0, protocol, dport, port_range);
}

static __always_inline void policy_add_egress_allow_all_entry(void)
{
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0);
}

static __always_inline void policy_add_egress_deny_all_entry(void)
{
	policy_add_entry(true, 0, 0, 0, 0, true, 0);
}

static __always_inline void
policy_delete_egress_l3_l4_entry(__u32 sec_label, __u8 protocol, __be16 dport,
				 __u8 port_range)
{
	policy_delete_entry(true, sec_label, protocol, dport, port_range);
}

static __always_inline void
policy_delete_egress_l3_entry(__u32 sec_label)
{
	policy_delete_egress_l3_l4_entry(sec_label, 0, 0, 0);
}

static __always_inline void
policy_delete_egress_l4_entry(__u8 protocol, __be16 dport, __u8 port_range)
{
	policy_delete_egress_l3_l4_entry(0, protocol, dport, port_range);
}

static __always_inline void policy_delete_egress_all_entry(void)
{
	policy_delete_egress_l3_l4_entry(0, 0, 0, 0);
}

static __always_inline void
policy_add_shared_entry(__u32 handle, __u32 identity, __u8 dir, __u8 proto, __be16 port, bool deny)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port, 0);
	__u32 key_prefix_len = SHARED_POLICY_FULL_PREFIX - wildcard_bits;
	__u8 value_prefix_len = LPM_FULL_PREFIX_BITS - wildcard_bits;

	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = key_prefix_len },
		.rule_set_id = handle,
		.sec_label = identity,
		.egress = dir,
		.pad = 0,
		.protocol = proto,
		.dport = port,
	};
	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = value_prefix_len,
		.proxy_port = 0,
		.auth_type = 0,
		.precedence = deny ? MAX_PRECEDENCE : 0,
		.cookie = 0,
	};

	map_update_elem(&cilium_policy_shared, &key, &value, BPF_ANY);
}

static __always_inline void
policy_add_shared_entry_full(__u32 handle, __u32 identity, __u8 dir, __u8 proto,
			     __be16 port, __u16 port_mask, bool deny,
			     __u8 auth_type, __be16 proxy_port)
{
	/* Calculate prefix length based on port mask */
	__u8 port_wildcard_bits = 0;

	if (port_mask == 0) {
		port_wildcard_bits = 16;
	} else if (port_mask != 0xFFFF) {
		/* Count trailing zeros in mask to get wildcard bits */
		__u16 m = port_mask;

		while ((m & 1) == 0 && port_wildcard_bits < 16) {
			port_wildcard_bits++;
			m >>= 1;
		}
	}

	__u8 proto_wildcard_bits = 0;

	if (proto == 0) {
		proto_wildcard_bits = 8;
		port_wildcard_bits = 16; /* Protocol wildcard implies port wildcard */
	}

	__u8 wildcard_bits = proto_wildcard_bits + port_wildcard_bits;
	__u32 key_prefix_len = SHARED_POLICY_FULL_PREFIX - wildcard_bits;
	__u8 value_prefix_len = LPM_FULL_PREFIX_BITS - wildcard_bits;

	struct shared_policy_key key = {
		.lpm_key = { .prefixlen = key_prefix_len },
		.rule_set_id = handle,
		.sec_label = identity,
		.egress = dir,
		.pad = 0,
		.protocol = proto,
		.dport = port & bpf_htons(port_mask), /* Apply mask to port in correct byte order */
	};

	struct policy_entry value = {
		.deny = deny,
		.lpm_prefix_length = value_prefix_len,
		.proxy_port = proxy_port,
		.auth_type = auth_type & 0x7f,
		.has_explicit_auth_type = (auth_type >> 7) & 0x1,
		.precedence = deny ? MAX_PRECEDENCE : 0,
		.cookie = 0,
	};

	map_update_elem(&cilium_policy_shared, &key, &value, BPF_ANY);
}

static __always_inline void
policy_update_overlay(__u32 endpoint_id, __u32 shared_handle)
{
	__u32 value = shared_handle;

	map_update_elem(&cilium_policy_overlay, &endpoint_id, &value, BPF_ANY);
}

