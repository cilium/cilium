#include "event.h"

#ifndef __NR_CPUS__
#define __NR_CPUS__ 1
#endif

struct bpf_elf_map __section_maps perf_test_events = {
	.type           = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.size_key       = sizeof(int),
	.size_value     = sizeof(int),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = __NR_CPUS__,
};

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	struct event_msg msg = {0};

	msg.type = EVENT_TYPE_SAMPLE;

	skb_load_bytes(skb, 0, &msg.data, sizeof(msg.data));
	skb_event_output(skb, &perf_test_events, BPF_F_CURRENT_CPU,
		     &msg, sizeof(msg));

	return TC_ACT_OK;
}

BPF_LICENSE("GPL");
