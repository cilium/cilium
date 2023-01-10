#include <linux/bpf.h>

#ifndef __section
# define __section(NAME)                  \
	   __attribute__((section(NAME), used))
#endif

__section("prog")
int xdp_foo(struct xdp_md *ctx)
{
	    return XDP_PASS;
}

char __license[] __section("license") = "GPL";
