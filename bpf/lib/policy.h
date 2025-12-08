/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/icmp.h>

#include "common.h"

#ifndef bpf_probe_read_kernel
static int BPF_FUNC(probe_read_kernel, void *dst, __u32 size, const void *unsafe_ptr);
# define bpf_probe_read_kernel probe_read_kernel
#endif
#include "dbg.h"
#include <bpf/compiler.h>
#include <bpf/api.h>

#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA 33
#endif

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

/*
 * Arena pointer address space attribute.
 * Clang uses address_space(1) for arena pointers in BPF programs.
 * This enables the compiler to generate proper addr_space_cast instructions.
 */
#ifdef ENABLE_BPF_ARENA
# ifndef __arena
#  define __arena __attribute__((address_space(1)))
# endif

/*
 * Cast helpers for arena pointers.
 * cast_kern: Convert arena pointer to kernel pointer (for dereferencing)
 * cast_user: Convert kernel pointer to arena pointer
 */
# if __clang_major__ >= 18
#  define cast_kern(ptr) ((typeof(*(ptr)) *)(__u64)(ptr))
#  define cast_user(ptr) ((typeof(ptr) __arena)(__u64)(ptr))
# else
/* Fallback for older clang - direct cast (may not work with verifier) */
#  define cast_kern(ptr) ((void *)(__u64)(ptr))
#  define cast_user(ptr) ((void *)(__u64)(ptr))
# endif
#else
# define __arena
# define cast_kern(ptr) ((void *)(__u64)(ptr))
# define cast_user(ptr) ((void *)(__u64)(ptr))
#endif


DECLARE_CONFIG(bool, allow_icmp_frag_needed,
	       "Allow ICMP_FRAG_NEEDED messages when applying Network Policy")
DECLARE_CONFIG(bool, enable_icmp_rule, "Apply Network Policy for ICMP packets")

#ifndef EFFECTIVE_EP_ID
#define EFFECTIVE_EP_ID 0
#endif

enum {
	POLICY_INGRESS = 1,
	POLICY_EGRESS = 2,
};

enum {
	POLICY_MATCH_NONE = 0,
	POLICY_MATCH_L3_ONLY = 1,
	POLICY_MATCH_L3_L4 = 2,
	POLICY_MATCH_L4_ONLY = 3,
	POLICY_MATCH_ALL = 4,
	POLICY_MATCH_L3_PROTO = 5,
	POLICY_MATCH_PROTO_ONLY = 6,
};

/*
 * Longest-prefix match map lookup only matches the number of bits from the
 * beginning of the key stored in the map indicated by the 'lpm_key' field in
 * the same stored map key, not including the 'lpm_key' field itself. Note that
 * the 'lpm_key' value passed in the lookup function argument needs to be a
 * "full prefix" (POLICY_FULL_PREFIX defined below).
 *
 * Since we need to be able to wildcard 'sec_label' independently on 'protocol'
 * and 'dport' fields, we'll need to do that explicitly with a separate lookup
 * where 'sec_label' is zero. For the 'protocol' and 'port' we can use the
 * longest-prefix match by placing them at the end ot the key in this specific
 * order, as we want to be able to wildcard those fields in a specific pattern:
 * 'protocol' can only be wildcarded if dport is also fully wildcarded.
 * 'protocol' is never partially wildcarded, so it is either fully wildcarded or
 * not wildcarded at all. 'dport' can be partially wildcarded, but only when
 * 'protocol' is fully specified. This follows the logic that the destination
 * port is a property of a transport protocol and can not be specified without
 * also specifying the protocol.
 */
struct policy_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32		sec_label;
	__u8		egress:1,
			pad:7;
	__u8		protocol; /* can be wildcarded if 'dport' is fully wildcarded */
	__be16		dport; /* can be wildcarded with CIDR-like prefix */
};

/* POLICY_FULL_PREFIX gets full prefix length of policy_key */
#define POLICY_FULL_PREFIX						\
  (8 * (sizeof(struct policy_key) - sizeof(struct bpf_lpm_trie_key)))

struct policy_entry {
	__be16		proxy_port;
	__u8		deny:1,
			reserved:2, /* bits used in Cilium 1.16, keep unused for Cilium 1.17 */
			lpm_prefix_length:5; /* map key protocol and dport prefix length */
	__u8		auth_type:7,
			has_explicit_auth_type:1;
	__u32		precedence;
	__u32		cookie;
};

/*
 * LPM_FULL_PREFIX_BITS is the maximum length in 'lpm_prefix_length' when none of the protocol or
 * dport bits in the key are wildcarded.
 */
#define LPM_PROTO_PREFIX_BITS 8                             /* protocol specified */
#define LPM_FULL_PREFIX_BITS (LPM_PROTO_PREFIX_BITS + 16)   /* protocol and dport specified */

/* Highest possible precedence */
#define MAX_PRECEDENCE (~0U)

/*
 * policy_stats_key has the same layout as policy_key, apart from the first four bytes.
 */
struct policy_stats_key {
	__u16		endpoint_id;
	__u8		pad1;
	__u8		prefix_len;
	__u32		sec_label;
	__u8		egress:1,
			pad:7;
	__u8		protocol; /* can be wildcarded if 'dport' is fully wildcarded */
	__be16		dport; /* can be wildcarded with CIDR-like prefix */
};

struct policy_stats_value {
	__u64		packets;
	__u64		bytes;
};

/* Global policy stats map */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct policy_stats_key);
	__type(value, struct policy_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} cilium_policystats __section_maps_btf;

static __always_inline void
__policy_account(__u32 remote_id, __u8 egress, __u8 proto, __be16 dport, __u8 lpm_prefix_length,
		 __u64 bytes)
{
	struct policy_stats_value *value;
	struct policy_stats_key stats_key = {
		.endpoint_id = EFFECTIVE_EP_ID,
		.pad1 = 0,
		.prefix_len = lpm_prefix_length,
		.sec_label = remote_id,
		.egress = egress,
		.pad = 0,
	};

	/*
	 * Must compute the wildcarded protocol and port for the policy stats map key.
	 * If bpf lookup ever returned the key of the matching entry we would not need
	 * to do this.
	 */
	if (lpm_prefix_length <= LPM_PROTO_PREFIX_BITS) {
		if (lpm_prefix_length < LPM_PROTO_PREFIX_BITS) {
			/* Protocol is not partially maskable */
			proto = 0;
		}
		dport = 0;
	} else if (lpm_prefix_length < LPM_FULL_PREFIX_BITS) {
		dport &= bpf_htons((__u16)(0xffff << (LPM_FULL_PREFIX_BITS - lpm_prefix_length)));
	}
	stats_key.protocol = proto;
	stats_key.dport = dport;

	value = map_lookup_elem(&cilium_policystats, &stats_key);

	if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, bytes);
	} else {
		struct policy_stats_value newval = { 1, bytes };

		map_update_elem(&cilium_policystats, &stats_key, &newval, BPF_NOEXIST);
	}
}

/* Per-endpoint policy enforcement map */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_policy_v2 __section_maps_btf;
/* Phase 3 Global Rules & List Maps */


/*
 * Check if a rule's port prefix covers a target port.
 *
 * LPM prefix length semantics:
 * - LPM_PROTO_PREFIX_BITS (8) = protocol only, port wildcarded
 * - 9-24 = protocol + (lpm_len - 8) bits of port
 * - LPM_FULL_PREFIX_BITS (24) = exact port match
 *
 * For a rule with base port P and prefix length L:
 * - If L <= LPM_PROTO_PREFIX_BITS: any port matches (wildcarded)
 * - If L > LPM_PROTO_PREFIX_BITS: check if target port's upper bits match
 *
 * Ports are in network byte order (big-endian)
 */
static __always_inline bool
port_prefix_matches(__be16 rule_port, __u8 lpm_prefix_len, __be16 target_port)
{
	/* If prefix doesn't include any port bits, any port matches */
	if (lpm_prefix_len <= LPM_PROTO_PREFIX_BITS)
		return true;

	/* Calculate how many port bits are significant */
	__u8 port_bits = lpm_prefix_len - LPM_PROTO_PREFIX_BITS;
	if (port_bits >= 16)
		return rule_port == target_port; /* Exact match */

	__u16 host_mask = (__u16)(0xFFFF << (16 - port_bits));
	__be16 mask = bpf_htons(host_mask);

	return (rule_port & mask) == (target_port & mask);
}

#define MAX_SHARED_REFS 16
#define MAX_PRIVATE_OVERRIDES 8

struct overlay_private_entry {
	struct policy_key key;
	struct policy_entry entry;
} __attribute__((packed));

struct overlay_entry {
	__u8 shared_ref_count;
	__u8 private_count;
	__u8 pad[2];
	__u32 shared_handles[MAX_SHARED_REFS];
	struct overlay_private_entry private_overrides[MAX_PRIVATE_OVERRIDES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct overlay_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_policy_o __section_maps_btf;


#if defined(ENABLE_BPF_ARENA) && !defined(BPF_ALIGN_CHECKER)
/* Arena Map Declaration - must match Go definition */
struct {
	__uint(type, 33); /* BPF_MAP_TYPE_ARENA */
	__uint(map_flags, (1U << 10)); /* BPF_F_MMAPABLE */
	__uint(max_entries, 4096); /* 4096 Pages = 16MB */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(key_size, 0);
	__uint(value_size, 0);
} cilium_policy_a __section_maps_btf __attribute__((used));

DECLARE_CONFIG(__u64, arena_base_addr, "BPF Arena base address")

/* Get arena base address from JIT constant */
static __always_inline __u64 get_arena_base_addr(void)
{
	return CONFIG(arena_base_addr);
}


/*
 * Components:
 * - cilium_policy_s: Global LPM trie with rule_set_id in key
 * - cilium_policy_arena: Arena memory for full policy_entry data
 * - cilium_policy_o: Per-endpoint mapping to rule_set_ids
 *
 * Lookup flow:
 * 1. Get endpoint's rule_set_ids from overlay
 * 2. For each rule_set_id, do LPM lookup
 * 3. Read full rule data from arena using arena_offset
 * 4. Select best match by precedence
 */

/*
 * Configurable limits - control memory usage
 */
#define SHARED_LPM_MAX_ENTRIES    131072
#define ARENA_MAX_RULE_DATA       65536

/*
 * Shared LPM Trie Key
 *
 * The key includes rule_set_id to enable sharing:
 * - Multiple endpoints can reference the same rule_set_id
 * - LPM matching is done on (protocol, dport)
 *
 * Key layout for LPM matching:
 *   Bytes 0-3:   lpm_key.prefixlen (always full prefix for lookup)
 *   Bytes 4-7:   rule_set_id (32 bits, always exact match)
 *   Bytes 8-11:  sec_label/identity (32 bits, always exact match)
 *   Byte  12:    egress flag (1 bit) + pad (7 bits)
 *   Byte  13:    protocol (8 bits, LPM matched)
 *   Bytes 14-15: dport (16 bits, LPM matched)
 *
 * The prefixlen covers: rule_set_id(32) + sec_label(32) + egress(8) + proto(8) + dport(16)
 * Total matchable bits: 96 bits = 12 bytes
 * For LPM on proto+dport only: prefixlen = 72 + (0 to 24)
 */
struct shared_lpm_key {
	struct bpf_lpm_trie_key lpm_key;  /* Must be first */
	__u32 rule_set_id;                /* Identifies the rule set (for sharing) */
	__u32 sec_label;                  /* Remote identity (0 for L4-only) */
	__u8  egress:1,                   /* Direction: 0=ingress, 1=egress */
	      pad:7;
	__u8  protocol;                   /* L4 protocol (can be LPM wildcarded) */
	__be16 dport;                     /* Destination port (can be LPM wildcarded) */
} __attribute__((packed));

/*
 * Full prefix length for shared_policy_key (excluding lpm_key itself)
 * = rule_set_id(32) + sec_label(32) + egress_pad(8) + protocol(8) + dport(16) = 96 bits
 */
#define SHARED_POLICY_FULL_PREFIX 96

/*
 * Base prefix for exact match on rule_set_id + sec_label + direction
 * = 32 + 32 + 8 = 72 bits
 * Add 0-24 for protocol+port matching
 */
#define SHARED_POLICY_BASE_PREFIX 72

/*
 * Shared LPM Trie Value
 *
 * Points to full rule data in arena memory.
 */
struct shared_lpm_value {
	__u32 arena_offset;     /* Offset in arena to policy_entry data */
	__u8  flags;            /* deny:1, reserved:2, lpm_prefix_length:5 */
	__u8  auth_type;        /* auth_type:7, has_explicit_auth_type:1 */
	__be16 proxy_port;      /* Proxy redirect port (fast path - avoid arena read) */
} __attribute__((packed));

/*
 * Shared Policy LPM Trie Map
 *
 * Global LPM trie shared by all endpoints. The rule_set_id in the key
 * enables multiple endpoints to share the same policy rules.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct shared_lpm_key);
	__type(value, struct shared_lpm_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SHARED_LPM_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_policy_s __section_maps_btf;

/*
 * Arena Rule Data
 *
 * Full policy entry data stored in arena for deduplication.
 */
struct arena_policy_entry {
	__be16 proxy_port;
	__u8   deny:1,
	       reserved:2,
	       lpm_prefix_length:5;
	__u8   auth_type:7,
	       has_explicit_auth_type:1;
	__u32  precedence;
	__u32  cookie;
} __attribute__((packed));

/*
 * Arena access helpers using bpf_probe_read_user().
 *
 * We cannot cast a scalar address to __arena pointer - the verifier
 * rejects the addr_space_cast. Instead, we use bpf_probe_read_user()
 * to safely read from the arena memory for now.
 */



/* Helper for probe_read_user if not available */
#ifndef bpf_probe_read_user
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
#endif


/* Read arena policy entry at given offset */
static __always_inline void arena_read_policy_entry(struct arena_policy_entry *dst, __u64 base, __u32 offset)
{
	__u64 addr = base + offset;
	bpf_probe_read_user(dst, sizeof(*dst), (void *)addr);
}

/*
 * Perform a single LPM lookup on the shared policy trie.
 * Returns the matching value or NULL if no match.
 */
static __always_inline struct shared_lpm_value *
shared_policy_lookup(__u32 rule_set_id, __u32 identity, __u8 egress,
		     __u8 proto, __be16 port)
{
	struct shared_lpm_key key = {
		.lpm_key = { .prefixlen = SHARED_POLICY_FULL_PREFIX },
		.rule_set_id = rule_set_id,
		.sec_label = identity,
		.egress = egress,
		.pad = 0,
		.protocol = proto,
		.dport = port,
	};
	return map_lookup_elem(&cilium_policy_s, &key);
}

/*
 * Update best match based on LPM prefix length and precedence.
 * This is called after each LPM lookup to track the best result.
 *
 * Returns true if this match is better than the current best.
 */
static __always_inline bool
shared_policy_update_best(struct shared_lpm_value *candidate,
			  struct shared_lpm_value **best,
			  __u32 *best_precedence, __u8 *best_lpm,
			  bool *best_is_l3, bool is_l3,
			  __u64 arena_base)
{
	if (!candidate)
		return false;

	__u8 cand_lpm = (candidate->flags >> 3) & 0x1f;
	bool cand_deny = candidate->flags & 0x1;

	/* Read precedence from arena for comparison */
	__u32 cand_precedence = 0;
	if (candidate->arena_offset != 0 && arena_base != 0) {
		struct arena_policy_entry entry;
		arena_read_policy_entry(&entry, arena_base, candidate->arena_offset);
		cand_precedence = entry.precedence;
	}

	/* Check if this is a better match:
	 * 1. Higher precedence wins
	 * 2. Same precedence: deny wins over allow
	 * 3. Same precedence and deny: longer LPM prefix wins
	 * 4. Same precedence, deny and LPM: L3 match preferred over L4-only
	 */
	bool better = false;
	if (!*best) {
		better = true;
	} else if (cand_precedence > *best_precedence) {
		better = true;
	} else if (cand_precedence == *best_precedence) {
		bool best_deny = (*best)->flags & 0x1;
		if (cand_deny && !best_deny) {
			better = true;
		} else if (cand_deny == best_deny) {
			if (cand_lpm > *best_lpm) {
				better = true;
			} else if (cand_lpm == *best_lpm && is_l3 && !*best_is_l3) {
				better = true;
			}
		}
	}

	if (better) {
		*best = candidate;
		*best_precedence = cand_precedence;
		*best_lpm = cand_lpm;
		*best_is_l3 = is_l3;
		return true;
	}
	return false;
}

/*
 * Macro to perform LPM lookup for a single rule set.
 * Used in the unrolled lookup loop below.
 */
#define SHARED_LOOKUP_RULE_SET(idx, rule_set_id, remote_id, egress, proto, port, arena_base, \
			       best, best_prec, best_lpm, best_is_l3) \
	do { \
		/* L3 lookup (specific identity) */ \
		struct shared_lpm_value *_l3 = shared_policy_lookup( \
			rule_set_id, remote_id, egress, proto, port); \
		shared_policy_update_best(_l3, &best, &best_prec, &best_lpm, \
					  &best_is_l3, true, arena_base); \
		/* L4-only lookup (identity = 0) */ \
		struct shared_lpm_value *_l4 = shared_policy_lookup( \
			rule_set_id, 0, egress, proto, port); \
		shared_policy_update_best(_l4, &best, &best_prec, &best_lpm, \
					  &best_is_l3, false, arena_base); \
	} while (0)

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                    \
        ({                                                      \
                char ____fmt[] = fmt;                           \
                trace_printk(____fmt, sizeof(____fmt),      \
                                 ##__VA_ARGS__);                \
        })
#endif

#endif // ENABLE_BPF_ARENA && !BPF_ALIGN_CHECKER

#if !defined(ENABLE_BPF_ARENA) && !defined(BPF_ALIGN_CHECKER)
/* Dummy map to satisfy loader expectation for cilium_policy_a in legacy builds */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, 4);
	__uint(value_size, 4);
	__uint(max_entries, 1);
} cilium_policy_a __section_maps_btf __attribute__((used));
#endif
//#endif // ENABLE_BPF_ARENA


static __always_inline int
policy_key_matches(struct policy_key *rule_key, struct policy_key *packet_key)
{
	__u32 prefixlen = rule_key->lpm_key.prefixlen;
	__u8 *rule_data = (__u8 *)rule_key + sizeof(struct bpf_lpm_trie_key);
	__u8 *pkt_data  = (__u8 *)packet_key + sizeof(struct bpf_lpm_trie_key);
	unsigned int i;
	
	/* Match full bytes */
	#pragma unroll
	for (i = 0; i < 8; i++) {
		if (i >= prefixlen / 8) break;
		if (rule_data[i] != pkt_data[i]) return 0;
	}

	/* Match remaining bits */
	__u8 bits = prefixlen % 8;
	if (bits) {
		__u8 mask = (__u8)(0xff << (8 - bits));
		if ((rule_data[i] & mask) != (pkt_data[i] & mask)) return 0;
	}
	return 1;
}

static __always_inline void
policy_update_best(struct policy_entry **best, struct policy_entry *cand, bool *best_is_l3, bool cand_is_l3)
{
	if (!cand) return;
	if (!*best) {
		*best = cand;
		*best_is_l3 = cand_is_l3;
		return;
	}
	if (cand->precedence > (*best)->precedence) {
		*best = cand;
		*best_is_l3 = cand_is_l3;
	} else if (cand->precedence == (*best)->precedence) {
		if (cand->lpm_prefix_length > (*best)->lpm_prefix_length) {
			*best = cand;
			*best_is_l3 = cand_is_l3;
		}
	}
}

struct policy_lookup_info {
	__u32 local_id;
	__u32 remote_id;
	__u8 direction;
	__u8 proto;
	__be16 port;
};


static __noinline __maybe_unused bool
policy_lookup_shared(struct policy_lookup_info *info, bool *is_l3_match, struct policy_entry *result)
{
	if (!result) return false;

	/* Use EFFECTIVE_EP_ID (endpoint ID) to look up the overlay map.
	 * The agent indexes the overlay map by endpoint ID, not security identity.
	 * info->local_id contains the security identity which is wrong for this lookup.
	 */
	__u32 ep_id = EFFECTIVE_EP_ID;

	struct overlay_entry *overlay = map_lookup_elem(&cilium_policy_o, &ep_id);
	if (!overlay)
		return false;

	/* Pre-initialize match flags */
	*is_l3_match = false;
	bool found = false;
	unsigned int i;

	struct policy_key pkt_key = {
		.lpm_key = { 0 },
		.sec_label = info->remote_id,
		.egress = (info->direction == POLICY_EGRESS) ? 1 : 0,
		.pad = 0,
		.protocol = info->proto,
		.dport = info->port,
	};

	/* 1. Check Private Overrides (highest precedence) */
	#pragma clang loop unroll(disable)
	for (i = 0; i < MAX_PRIVATE_OVERRIDES; i++) {
		if (i >= overlay->private_count) break;
		struct overlay_private_entry *p = &overlay->private_overrides[i];
		if (policy_key_matches(&p->key, &pkt_key)) {
			bool l3 = (p->key.lpm_key.prefixlen >= 32);
			if (!found || p->entry.precedence > result->precedence ||
			    (p->entry.precedence == result->precedence && p->entry.lpm_prefix_length > result->lpm_prefix_length)) {
				*result = p->entry;
				*is_l3_match = l3;
				found = true;
			}
			if (result->deny && result->precedence == MAX_PRECEDENCE)
				return true;
		}
	}

	/* Phase 3 Lookup: Traverse Rule Set List in Shared LPM Trie */
	if (overlay->shared_ref_count > 0) {

#if defined(ENABLE_BPF_ARENA) && !defined(BPF_ALIGN_CHECKER)
		__u8 direction = info->direction;
		__u8 egress = (direction == POLICY_EGRESS) ? 1 : 0;
		__u8 proto = info->proto;
		__be16 port = info->port;

		/* Get arena base address for reading full rule data */
		__u64 arena_base = get_arena_base_addr();

		/* Best match tracking */
		struct shared_lpm_value *best = NULL;
		__u32 best_prec = 0;
		__u8 best_lpm = 0;
		bool best_is_l3 = false;

		/*
		 * Unrolled lookups for each rule set.
		 * MAX_SHARED_REFS = 16, so we do up to 32 LPM lookups (L3 + L4 each).
		 * Each lookup is O(log n).
		 */

		/* Rule set 0 */
		if (overlay->shared_ref_count > 0) {
			SHARED_LOOKUP_RULE_SET(0, overlay->shared_handles[0],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 1 */
		if (overlay->shared_ref_count > 1) {
			SHARED_LOOKUP_RULE_SET(1, overlay->shared_handles[1],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 2 */
		if (overlay->shared_ref_count > 2) {
			SHARED_LOOKUP_RULE_SET(2, overlay->shared_handles[2],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 3 */
		if (overlay->shared_ref_count > 3) {
			SHARED_LOOKUP_RULE_SET(3, overlay->shared_handles[3],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 4 */
		if (overlay->shared_ref_count > 4) {
			SHARED_LOOKUP_RULE_SET(4, overlay->shared_handles[4],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 5 */
		if (overlay->shared_ref_count > 5) {
			SHARED_LOOKUP_RULE_SET(5, overlay->shared_handles[5],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 6 */
		if (overlay->shared_ref_count > 6) {
			SHARED_LOOKUP_RULE_SET(6, overlay->shared_handles[6],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 7 */
		if (overlay->shared_ref_count > 7) {
			SHARED_LOOKUP_RULE_SET(7, overlay->shared_handles[7],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 8 */
		if (overlay->shared_ref_count > 8) {
			SHARED_LOOKUP_RULE_SET(8, overlay->shared_handles[8],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 9 */
		if (overlay->shared_ref_count > 9) {
			SHARED_LOOKUP_RULE_SET(9, overlay->shared_handles[9],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 10 */
		if (overlay->shared_ref_count > 10) {
			SHARED_LOOKUP_RULE_SET(10, overlay->shared_handles[10],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 11 */
		if (overlay->shared_ref_count > 11) {
			SHARED_LOOKUP_RULE_SET(11, overlay->shared_handles[11],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 12 */
		if (overlay->shared_ref_count > 12) {
			SHARED_LOOKUP_RULE_SET(12, overlay->shared_handles[12],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 13 */
		if (overlay->shared_ref_count > 13) {
			SHARED_LOOKUP_RULE_SET(13, overlay->shared_handles[13],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 14 */
		if (overlay->shared_ref_count > 14) {
			SHARED_LOOKUP_RULE_SET(14, overlay->shared_handles[14],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}
		/* Rule set 15 */
		if (overlay->shared_ref_count > 15) {
			SHARED_LOOKUP_RULE_SET(15, overlay->shared_handles[15],
					       info->remote_id, egress, proto, port, arena_base,
					       best, best_prec, best_lpm, best_is_l3);
		}

		/* Convert best match to policy_entry result */
		if (best) {
			/* Read full rule data from arena */
			if (best->arena_offset != 0 && arena_base != 0) {
				struct arena_policy_entry entry;
				arena_read_policy_entry(&entry, arena_base, best->arena_offset);

				result->proxy_port = entry.proxy_port;
				result->deny = entry.deny;
				result->lpm_prefix_length = entry.lpm_prefix_length;
				result->auth_type = entry.auth_type;
				result->has_explicit_auth_type = entry.has_explicit_auth_type;
				result->precedence = entry.precedence;
				result->cookie = entry.cookie;
			} else {
				/* Fast path: use data from LPM value directly */
				result->proxy_port = best->proxy_port;
				result->deny = best->flags & 0x1;
				result->lpm_prefix_length = (best->flags >> 3) & 0x1f;
				result->auth_type = best->auth_type & 0x7f;
				result->has_explicit_auth_type = (best->auth_type >> 7) & 0x1;
				result->precedence = best_prec;
				result->cookie = 0;
			}

			*is_l3_match = best_is_l3;
			found = true;
		}

		(void)0; /* Label requires statement */
#endif /* ENABLE_BPF_ARENA */
	}

	return found;
}

/* Return a verdict for the chosen 'policy', possibly propagating the auth type from 'policy2', if
 * non-NULL and of the same precedence.
 *
 * Always called with non-NULL 'policy', while 'policy2' may be NULL.
 * If 'policy2' is non-null, it never has a higher precedence than 'policy'.
 */
static __always_inline int
__policy_check(const struct policy_entry *policy, const struct policy_entry *policy2, __s8 *ext_err,
	       __u16 *proxy_port, __u32 *cookie)
{
	/* auth_type is derived from the matched policy entry, except if both L3/L4 and L4-only
	 * match, and the chosen policy has no explicit auth type: in this case the auth type is
	 * derived from the less specific policy entry.
	 */
	__u8 auth_type;

	*cookie = policy->cookie;

	if (unlikely(policy->deny))
		return DROP_POLICY_DENY;

	/* The chosen 'policy' has higher precedence or if on the same precedence it has more
	 * specific L4 match, or if also the L4 are equally specific, then the chosen policy has
	 * an L3 match, which is considered to be more specific.
	 * If precedence is the same, then by definition either both have a proxy
	 * redirect or neither has one, so we do not need to check if the other policy has a proxy
	 * redirect or not.
	 */
	*proxy_port = policy->proxy_port;

	auth_type = policy->auth_type;
	/* Propagate the auth type from the same precedence, more general policy2 if needed. */
	if (unlikely(policy2 && policy2->precedence == policy->precedence &&
		     !policy->has_explicit_auth_type && policy2->auth_type > auth_type)) {
		auth_type = policy2->auth_type;
	}

	if (unlikely(auth_type)) {
		if (ext_err)
			*ext_err = (__s8)auth_type;
		return DROP_POLICY_AUTH_REQUIRED;
	}

	return *proxy_port ? (int)bpf_ntohs(*proxy_port) : CTX_ACT_OK;
}

/* Allow experimental access to the @map parameter. */
static __always_inline int
__policy_can_access(const void *map __maybe_unused, struct __ctx_buff *ctx,
		    __u32 local_id, __u32 remote_id, __u16 ethertype,
		    __be16 dport, __u8 proto, int off, int dir,
		    bool is_untracked_fragment, __u8 *match_type, __s8 *ext_err,
		    __u16 *proxy_port, __u32 *cookie)
{
	struct policy_key key = {
		.lpm_key = { POLICY_FULL_PREFIX, {} }, /* always look up with unwildcarded data */
		.sec_label = remote_id,
		.egress = !dir,
		.pad = 0,
		.protocol = proto,
		.dport = dport,
	};

	if (CONFIG(allow_icmp_frag_needed) || CONFIG(enable_icmp_rule)) {
		switch (ethertype) {
		case ETH_P_IP:
			if (proto == IPPROTO_ICMP) {
				struct icmphdr icmphdr __align_stack_8;

				if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
					return DROP_INVALID;

				if (CONFIG(allow_icmp_frag_needed)) {
					if (icmphdr.type == ICMP_DEST_UNREACH &&
					    icmphdr.code == ICMP_FRAG_NEEDED) {
						*proxy_port = 0;
						return CTX_ACT_OK;
					}
				}

				if (CONFIG(enable_icmp_rule))
					key.dport = bpf_u8_to_be16(icmphdr.type);
			}
			break;
		case ETH_P_IPV6:
			if (CONFIG(enable_icmp_rule)) {
				if (proto == IPPROTO_ICMPV6) {
					__u8 icmp_type;

					if (ctx_load_bytes(ctx, off, &icmp_type,
							   sizeof(icmp_type)) < 0)
						return DROP_INVALID;

					key.dport = bpf_u8_to_be16(icmp_type);
				}
			}
			break;
		default:
			break;
		}
	}

	/* Policy match precedence when both L3 and L4-only lookups find a matching policy:
	 *
	 * 1. Policy with the higher precedence value is selected. This includes giving precedence
	 *    to deny over allow, proxy redirect over non-proxy redirect, and proxy port priority.
	 * 2. The entry with longer prefix length is selected out of the two entries with the same
	 *    precedence.
	 * 3. Otherwise the allow entry with non-wildcard L3 is chosen.
	 */

	/* Note: Untracked fragments always have zero ports in the tuple so they can
	 * only match entries that have fully wildcarded ports.
	 */

#if defined(ENABLE_BPF_ARENA)
	/*
	 * Arena-based policy lookup - fully independent, no legacy fallback.
	 *
	 * The arena lookup handles all policy rules including:
	 * - L3 (specific identity) and L4-only (identity=0) lookups
	 * - Port range matching via LPM prefix
	 * - Deny rules with proper precedence handling
	 * - Auth type propagation between L3 and L4 matches
	 *
	 * All rules are offloaded to the arena, so no legacy LPM trie lookup needed.
	 */
	struct policy_lookup_info arena_info = {
		.local_id = local_id,
		.remote_id = remote_id,
		.direction = (dir == CT_EGRESS) ? POLICY_EGRESS : POLICY_INGRESS,
		.proto = proto,
		.port = key.dport, /* Use key.dport - may be modified by ICMP handling */
	};
	bool arena_is_l3_match = false;
	struct policy_entry arena_policy = {0};

	if (policy_lookup_shared(&arena_info, &arena_is_l3_match, &arena_policy)) {
		/* Arena match found - return the result */
		__u8 p_len = arena_policy.lpm_prefix_length;

		cilium_dbg3(ctx, DBG_L4_CREATE, remote_id, local_id,
			    bpf_ntohs(key.dport) << 16 | proto);

#ifdef POLICY_ACCOUNTING
		__policy_account(arena_is_l3_match ? remote_id : 0, key.egress, proto, key.dport,
				 p_len, ctx_full_len(ctx));
#endif

		if (arena_is_l3_match) {
			*match_type =
				p_len > LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_L3_L4 :
				p_len > 0 ? POLICY_MATCH_L3_PROTO :
				POLICY_MATCH_L3_ONLY;
		} else {
			*match_type =
				p_len == 0 ? POLICY_MATCH_ALL :
				p_len <= LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_PROTO_ONLY :
				POLICY_MATCH_L4_ONLY;
		}

		return __policy_check(&arena_policy, NULL, ext_err, proxy_port, cookie);
	}

	/* No match found in arena.
	 *
	 * For host-level programs, allow traffic when no match is found:
	 *
	 * 1. EFFECTIVE_EP_ID == 0: As I see programs like bpf_overlay.c that don't define
	 *    their own endpoint identity. In legacy mode, they don't enforce
	 *    policy at all.
	 *
	 * 2. IS_BPF_HOST: Programs like bpf_host.c (cil_to_host, cil_from_netdev)
	 *    that use host_ep_id. The host endpoint may not have rules for all
	 *    identities (e.g. remote-node identity 6). In legacy mode without
	 *    ENABLE_HOST_FIREWALL, these programs don't enforce policy. With
	 *    host firewall enabled, specific deny rules will still be matched
	 *    and enforced - only the "no match" case defaults to allow.
	 *
	 * Pod programs (bpf_lxc.c with LXC_ID) always enforce policy - they have
	 * complete rule sets and should DROP_POLICY on no match.
	 */
	if (EFFECTIVE_EP_ID == 0 || is_defined(IS_BPF_HOST)) {
		*match_type = POLICY_MATCH_ALL;
		return CTX_ACT_OK;
	}

	if (is_untracked_fragment)
		return DROP_FRAG_NOSUPPORT;

	return DROP_POLICY;

#else /* !ENABLE_BPF_ARENA */

	const struct policy_entry *policy;
	const struct policy_entry *l4policy;
	__u8 p_len;

	/* Legacy LPM trie lookup */
	/* L3 lookup: an exact match on L3 identity and LPM match on L4 proto and port. */
	policy = map_lookup_elem(map, &key);

	/* L3 policy can be chosen without the 2nd lookup if it has the highest possible precedence
	 * value (which implies that it is a deny).
	 */
	if (likely(policy)) {
		if (policy->precedence == MAX_PRECEDENCE) {
			l4policy = NULL;
			goto check_policy;
		}
	}

	/* L4-only lookup: a wildcard match on L3 identity and LPM match on L4 proto and port. */
	key.sec_label = 0;
	l4policy = map_lookup_elem(map, &key);

	/* The found l4policy is chosen if:
	 * - only l4 policy was found, or if both policies are found, and:
	 * 1. It has higher precedence value, or
	 * 2. Precedence is equal (which implies both are denys or both are allows) and
	 *    L4-only policy has longer LPM prefix length than the L3 policy
	 */
	if (l4policy &&
	    (!policy ||
	     l4policy->precedence > policy->precedence ||
	     (l4policy->precedence == policy->precedence &&
	      l4policy->lpm_prefix_length > policy->lpm_prefix_length)))
		goto check_l4_policy;

	/* 4. Otherwise select L3 policy if found. */
	if (likely(policy))
		goto check_policy;

	if (is_untracked_fragment)
		return DROP_FRAG_NOSUPPORT;

	return DROP_POLICY;

check_policy:
	cilium_dbg3(ctx, DBG_L4_CREATE, remote_id, local_id, dport << 16 | proto);
	p_len = policy->lpm_prefix_length;
#ifdef POLICY_ACCOUNTING
	__policy_account(remote_id, key.egress, proto, dport, p_len, ctx_full_len(ctx));
#endif
	*match_type =
		p_len > LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_L3_L4 :	/* 1. id/proto/port */
		p_len > 0 ? POLICY_MATCH_L3_PROTO :			/* 3. id/proto/ANY */
		POLICY_MATCH_L3_ONLY;					/* 5. id/ANY/ANY */
	return __policy_check(policy, l4policy, ext_err, proxy_port, cookie);

check_l4_policy:
	p_len = l4policy->lpm_prefix_length;
#ifdef POLICY_ACCOUNTING
	__policy_account(0, key.egress, proto, dport, p_len, ctx_full_len(ctx));
#endif
	*match_type =
		p_len == 0 ? POLICY_MATCH_ALL :					/* 6. ANY/ANY/ANY */
		p_len <= LPM_PROTO_PREFIX_BITS ? POLICY_MATCH_PROTO_ONLY :	/* 4. ANY/proto/ANY */
		POLICY_MATCH_L4_ONLY;						/* 2. ANY/proto/port */
	return __policy_check(l4policy, policy, ext_err, proxy_port, cookie);

#endif /* ENABLE_BPF_ARENA */
}

static __always_inline int
policy_can_access(struct __ctx_buff *ctx, __u32 local_id, __u32 remote_id,
		  __u16 ethertype, __be16 dport, __u8 proto, int off, int dir,
		  bool is_untracked_fragment, __u8 *match_type, __s8 *ext_err,
		  __u16 *proxy_port, __u32 *cookie)
{
	return __policy_can_access(&cilium_policy_v2, ctx, local_id, remote_id,
				   ethertype, dport, proto, off, dir,
				   is_untracked_fragment, match_type, ext_err,
				   proxy_port, cookie);
}

/**
 * Determine whether the policy allows this traffic on ingress.
 * @arg ctx		Packet to allow or deny
 * @arg src_id		Source security identity for this packet
 * @arg dst_id		Destination security identity for this packet
 * @arg ethertype	Ethertype of this packet
 * @arg dport		Destination port of this packet
 * @arg proto		L3 Protocol of this packet
 * @arg l4_off		Offset to L4 header of this packet
 * @arg is_untracked_fragment	True if packet is a TCP/UDP datagram fragment
 *				AND IPv4 fragment tracking is disabled
 * @arg match_type		Pointer to store layers used for policy match
 * @arg ext_err		Pointer to store extended error information if this packet isn't allowed
 * @arg proxy_port	Pointer to store port for proxy redirect
 * @arg cookie		Pointer to store policy log cookie, if any
 *
 * Returns:
 *   - Positive integer indicating the proxy_port to handle this traffic
 *   - CTX_ACT_OK if the policy allows this traffic based only on labels/L3/L4
 *   - Negative error code if the packet should be dropped
 */
static __always_inline int
policy_can_ingress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
		   __u16 ethertype, __be16 dport, __u8 proto, int l4_off,
		   bool is_untracked_fragment, __u8 *match_type, __u8 *audited,
		   __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;

	ret = policy_can_access(ctx, dst_id, src_id, ethertype, dport,
				proto, l4_off, CT_INGRESS, is_untracked_fragment,
				match_type, ext_err, proxy_port, cookie);
	if (ret >= CTX_ACT_OK)
		return ret;

	cilium_dbg(ctx, DBG_POLICY_DENIED, src_id, dst_id);

	*audited = 0;
#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif

	return ret;
}

static __always_inline int policy_can_ingress6(struct __ctx_buff *ctx,
					       const struct ipv6_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port,
					       __u32 *cookie)
{
	return policy_can_ingress(ctx, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port, cookie);
}

static __always_inline int policy_can_ingress4(struct __ctx_buff *ctx,
					       const struct ipv4_ct_tuple *tuple,
					       int l4_off, bool is_untracked_fragment,
					       __u32 src_id, __u32 dst_id,
					       __u8 *match_type, __u8 *audited,
					       __s8 *ext_err, __u16 *proxy_port,
					       __u32 *cookie)
{
	return policy_can_ingress(ctx, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, is_untracked_fragment,
				 match_type, audited, ext_err, proxy_port, cookie);
}

#ifdef HAVE_ENCAP
static __always_inline bool is_encap(__be16 dport, __u8 proto)
{
	return proto == IPPROTO_UDP && dport == bpf_htons(TUNNEL_PORT);
}
#endif

static __always_inline int
policy_can_egress(struct __ctx_buff *ctx, __u32 src_id, __u32 dst_id,
		  __u16 ethertype, __be16 dport, __u8 proto, int l4_off, __u8 *match_type,
		  __u8 *audited, __s8 *ext_err, __u16 *proxy_port, __u32 *cookie)
{
	int ret;

#ifdef HAVE_ENCAP
	if (src_id != HOST_ID && is_encap(dport, proto))
		return DROP_ENCAP_PROHIBITED;
#endif
	ret = policy_can_access(ctx, src_id, dst_id, ethertype, dport,
				proto, l4_off, CT_EGRESS, false, match_type,
				ext_err, proxy_port, cookie);
	if (ret >= 0)
		return ret;
	cilium_dbg(ctx, DBG_POLICY_DENIED, src_id, dst_id);
	*audited = 0;
#ifdef POLICY_AUDIT_MODE
	if (IS_ERR(ret)) {
		ret = CTX_ACT_OK;
		*audited = 1;
	}
#endif
	return ret;
}

static __always_inline int policy_can_egress6(struct __ctx_buff *ctx,
					      const struct ipv6_ct_tuple *tuple,
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port, __u32 *cookie)
{
	return policy_can_egress(ctx, src_id, dst_id, ETH_P_IPV6, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port, cookie);
}

static __always_inline int policy_can_egress4(struct __ctx_buff *ctx,
					      const struct ipv4_ct_tuple *tuple,
					      int l4_off, __u32 src_id, __u32 dst_id,
					      __u8 *match_type, __u8 *audited, __s8 *ext_err,
					      __u16 *proxy_port, __u32 *cookie)
{
	return policy_can_egress(ctx, src_id, dst_id, ETH_P_IP, tuple->dport,
				 tuple->nexthdr, l4_off, match_type, audited,
				 ext_err, proxy_port, cookie);
}
