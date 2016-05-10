#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "events.h"
#include "common.h"

#ifdef DROP_NOTIFY
static inline void send_drop_notify_error(struct __sk_buff *skb, __u8 error)
{
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.subtype = error,
		.flags = 0,
		.len = skb->len,
		.ifindex = skb->ingress_ifindex,
	};

	skb_load_bytes(skb, 0, &msg.data, sizeof(msg.data));
	event_output(&cilium_events, get_smp_processor_id(), &msg, sizeof(msg));
}

static inline void send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				    __u32 dst_id, __u32 ifindex)
{
	struct drop_notify msg = {
		.type = CILIUM_NOTIFY_DROP,
		.subtype = -(DROP_POLICY),
		.flags = 0,
		.len = skb->len,
		.src_label = src,
		.dst_label = dst,
		.dst_id = dst_id,
		.ifindex = ifindex,
	};

	skb_load_bytes(skb, 0, &msg.data, sizeof(msg.data));
	event_output(&cilium_events, get_smp_processor_id(), &msg, sizeof(msg));
}
#else
static inline void send_drop_notify_error(struct __sk_buff *skb, __u8 error)
{
}

static inline void send_drop_notify(struct __sk_buff *skb, __u32 src, __u32 dst,
				    __u32 dst_id, __u32 ifindex)
{
}
#endif

#endif /* __LIB_DROP__ */
