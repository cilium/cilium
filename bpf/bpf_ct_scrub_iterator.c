// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "lib/ct_tuple.h"

/* Stub out types that would normally be found in vmlinux.h to satisfy BTF type
 * checks for SEC("iter/bpf_map_elem").
 */
struct seq_file {};

struct bpf_iter_meta {
	struct seq_file *seq;
};

struct bpf_iter__bpf_map_elem {
	struct bpf_iter_meta *meta;
	struct bpf_map *map;
	void *key;
	void *value;
};

#define CT_FILTER_MATCH_IP	(1 << 0)
/* Emit a zeroed 14-byte ipv4_ct_tuple progress marker every 1,024
 * non-matching entries. Combined with userspace's 16-record (224-byte) read
 * buffer, bpf_seq_read() stops at seq->count >= size after scanning at most
 * 16 * 1,024 = 16,384 non-matching entries (~5 ms on a non-preemptible
 * kernel; empty buckets are walked without pacing) instead of running to
 * MAX_ITER_OBJECTS (1,000,000) without returning.
 */
#define CT_ITER_YIELD_INTERVAL	1024

struct ct_scrub_filter {
	__be32 target_ip;
	__u32 alive;
	__u16 filter_flags;
	__u16 pad;
};

/* Singleton filter map: index 0 holds active filter parameters. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ct_scrub_filter);
} cilium_ct_flt __section_maps_btf;

static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);

static __always_inline bool
ct_entry_matches_filter(const struct ct_scrub_filter *flt,
			const struct ipv4_ct_tuple *key)
{
	return key->saddr == flt->target_ip || key->daddr == flt->target_ip;
}

/* Attached ONLY to IPv4 conntrack maps (14-byte struct ipv4_ct_tuple key).
 * Callers MUST NOT attach this program to IPv6 conntrack maps: the kernel's
 * bpf_iter_attach_map() only checks that the target map's key_size is at least
 * the 14 bytes accessed here, so a 38-byte IPv6 CT tuple key would pass attach
 * validation and have its leading bytes misparsed as an IPv4 tuple.
 */
__section("iter/bpf_map_elem")
int cil_ct4_scrub(const struct bpf_iter__bpf_map_elem *ctx)
{
	struct ipv4_ct_tuple tuple __align_stack_8;
	struct seq_file *seq = ctx->meta->seq;
	const struct ipv4_ct_tuple *key = ctx->key;
	struct ct_scrub_filter *flt;
	__u32 zero = 0;

	build_bug_on(sizeof(struct ct_scrub_filter) != 12);
	build_bug_on(sizeof(struct ipv4_ct_tuple) != 14);
	build_bug_on(CT_ITER_YIELD_INTERVAL == 0 ||
		     (CT_ITER_YIELD_INTERVAL & (CT_ITER_YIELD_INTERVAL - 1)) != 0);

	/* On the terminal EOF invocation ctx->key is NULL. Read and validate
	 * ctx->key once before map_lookup_elem(): re-reading ctx->key after the
	 * helper call makes the verifier treat the reload as an unchecked
	 * rdonly_buf_or_null pointer, and returning early ensures EOF never
	 * increments flt->alive.
	 */
	if (!key)
		return 0;

	flt = map_lookup_elem(&cilium_ct_flt, &zero);
	/* Fail-closed: uninitialized, zeroed, or unspecified-IP filter matches
	 * nothing and must not increment alive.
	 */
	if (!flt || !(flt->filter_flags & CT_FILTER_MATCH_IP) || !flt->target_ip)
		return 0;

	/* Count only non-matching entries in kernel: matching candidates are
	 * deleted or re-checked against the filter during userspace purge.
	 * Every CT_ITER_YIELD_INTERVAL non-matching entries, emit a zeroed
	 * 14-byte marker so bpf_seq_read() hits userspace's small read chunk
	 * (seq->count >= size) and returns bounded passes on non-preemptible
	 * kernels. Real matching tuples always have non-zero saddr or daddr
	 * (target_ip != 0), so zero markers never collide and are discarded by
	 * decodeCTIterStream.
	 *
	 * Scans are serialized by userspace ctIterator.mu. The alive count
	 * stays exact only because 224-byte reads (<< 32 KiB seq_file buffer)
	 * cannot hit -EOVERFLOW and trigger element replay, which would re-run
	 * this program and double-count flt->alive; do not raise the read size
	 * near 32 KiB without accounting for replay.
	 */
	if (!ct_entry_matches_filter(flt, key)) {
		flt->alive++;
		if ((flt->alive & (CT_ITER_YIELD_INTERVAL - 1)) == 0) {
			memset(&tuple, 0, sizeof(tuple));
			seq_write(seq, &tuple, sizeof(tuple));
		}
		return 0;
	}

	/* Copy to stack so seq_write() receives PTR_TO_STACK rather than
	 * passing the kernel's read-only key buffer (PTR_TO_RDONLY_BUF) to a
	 * helper on any kernel. Ignore seq_write()'s return value defensively:
	 * if -EOVERFLOW occurs on an oversized (>= 32 KiB) read buffer,
	 * bpf_seq_read() replays the unconsumed element on the next read().
	 */
	memcpy(&tuple, key, sizeof(tuple));
	seq_write(seq, &tuple, sizeof(tuple));
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
