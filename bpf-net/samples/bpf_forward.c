#include "bpf_api.h"

#if 0
# tc filter add dev wlp2s0b1 parent ffff: bpf da obj examples/bpf/list/bpf_forward.o sec redir-recv
# tc filter show dev wlp2s0b1 parent ffff:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_forward.o:[redir-recv] direct-action 

# tc filter add dev wlp2s0b1 parent ffff: bpf da obj examples/bpf/list/bpf_forward.o sec redir-xmit
# tc filter show dev wlp2s0b1 parent ffff:
filter protocol all pref 49152 bpf 
filter protocol all pref 49152 bpf handle 0x1 bpf_forward.o:[redir-xmit] direct-action 
#endif

__section("redir-xmit")
int cls_entry_x(struct __sk_buff *skb)
{
	return redirect(1, 0); /* ifindex, xmit/rcv flag */
}

__section("redir-recv")
int cls_entry_r(struct __sk_buff *skb)
{
	return redirect(1, 1);
}

BPF_LICENSE("GPL");
