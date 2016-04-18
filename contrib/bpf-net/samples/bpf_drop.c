#include "bpf_api.h"

#if 0
# tc filter add dev wlp2s0b1 parent ffff: bpf da obj examples/bpf/list/bpf_drop.o 
# tc filter show dev wlp2s0b1 parent ffff:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_drop.o:[classifier] direct-action 
#endif

__section_cls_entry
int cls_entry(struct __sk_buff *skb)
{
	return TC_ACT_SHOT; /* or TC_ACT_STOLEN w/o stats update */
}

BPF_LICENSE("GPL");
