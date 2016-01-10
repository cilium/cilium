#include <iproute2/bpf_api.h>

__section("from-container")
int handle_ingress(struct __sk_buff *skb)
{
	return 0;
}
BPF_LICENSE("GPL");
