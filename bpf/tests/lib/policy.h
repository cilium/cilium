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

static __always_inline void
policy_add_shared_entry(__u32 handle, __u32 identity, __u8 dir, __u8 proto, __u16 port, bool deny)
{
	__u8 wildcard_bits = policy_calc_wildcard_bits(proto, port);
	__u32 key_prefix_len = SHARED_POLICY_FULL_PREFIX - wildcard_bits;
	__u8 value_prefix_len = LPM_FULL_PREFIX_BITS - wildcard_bits;

	struct shared_lpm_key key = {
		.lpm_key = { .prefixlen = key_prefix_len },
		.rule_set_id = handle,
		.sec_label = identity,
		.egress = dir,
		.pad = 0,
		.protocol = proto,
		.dport = port,
	};
	struct shared_lpm_value value = {
		.arena_offset = 0,
		.flags = (__u8)((deny ? 1 : 0) | (value_prefix_len << 3)),
		.auth_type = 0,
		.proxy_port = 0,
	};

	map_update_elem(&cilium_policy_s, &key, &value, BPF_ANY);
}

/*
 * Extended helper for shared policy entries with all fields.
 *
 * @handle: Rule set ID
 * @identity: Remote identity (0 for L4-only/wildcard)
 * @dir: Direction (0=ingress, 1=egress)
 * @proto: Protocol (0 for wildcard)
 * @port: Port in network byte order (0 for wildcard)
 * @port_mask: Port mask for LPM (0xFFFF for exact, less for range)
 * @deny: True for deny rule
 * @auth_type: Auth type (0 for none, with has_explicit bit in high bit)
 * @proxy_port: Proxy redirect port (0 for none)
 */
static __always_inline void
policy_add_shared_entry_full(__u32 handle, __u32 identity, __u8 dir, __u8 proto,
			     __u16 port, __u16 port_mask, bool deny,
			     __u8 auth_type, __u16 proxy_port)
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

	struct shared_lpm_key key = {
		.lpm_key = { .prefixlen = key_prefix_len },
		.rule_set_id = handle,
		.sec_label = identity,
		.egress = dir,
		.pad = 0,
		.protocol = proto,
		.dport = port & bpf_htons(port_mask), /* Apply mask to port in correct byte order */
	};

	/* Flags: deny(1) | reserved(2) | lpm_prefix_length(5) */
	__u8 flags = (__u8)((value_prefix_len << 3) | (deny ? 0x1 : 0));
	struct shared_lpm_value value = {
		.arena_offset = 0,
		.flags = flags,
		.auth_type = auth_type,
		.proxy_port = proxy_port,
	};

	map_update_elem(&cilium_policy_s, &key, &value, BPF_ANY);
}

static __always_inline void
policy_update_overlay(__u32 endpoint_id, __u32 shared_handle)
{
	struct overlay_entry value = {0};
	value.shared_ref_count = 1;
	value.shared_handles[0] = shared_handle;
	
	map_update_elem(&cilium_policy_o, &endpoint_id, &value, BPF_ANY);
}
