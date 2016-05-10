#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "common.h"

struct bpf_elf_map __section_maps cilium_events = {
	.type           = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key       = sizeof(__u32),
	.size_value     = sizeof(__u32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = __NR_CPUS__,
};

#ifdef DROP_NOTIFY
static inline void send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				    __u32 dst_id, __u32 ifindex)
{
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.subtype = 0,
		.flags = 0,
		.len = skb->len,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.dst_ifindex = ifindex,
	};

	skb_load_bytes(skb, 0, &msg.data, sizeof(msg.data));
	event_output(&cilium_events, get_smp_processor_id(), &msg, sizeof(msg));
}
#else
static inline void send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				    __u32 dst_id, __u32 ifindex)
{
}
#endif

#endif /* __LIB_DROP__ */
