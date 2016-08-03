#include <bpf/api.h>

__section("probe")
int probe_skb_change_tail(struct __sk_buff *skb)
{
	if (skb->cb[0] != 0)
		skb_change_tail(skb, 0);

	return TC_ACT_SHOT;
}

BPF_LICENSE("GPL");
