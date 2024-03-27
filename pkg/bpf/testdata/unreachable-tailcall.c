#include <bpf/loader.h>
#include <bpf/section.h>

#include <bpf/ctx/skb.h>
#include <bpf/tailcall.h>

#define CILIUM_MAP_CALLS 2

volatile const int global_var = 0;

struct bpf_elf_map __section_maps cilium_calls_test = {
	.type		= BPF_MAP_TYPE_PROG_ARRAY,
	.id		= CILIUM_MAP_CALLS,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(__u32),
	.max_elem	= 5,
};

#define TAIL_A 0
#define TAIL_B 1
#define TAIL_C 2
#define TAIL_D 3
#define TAIL_E 4

__section_tail(CILIUM_MAP_CALLS, TAIL_E)
static int e(void *ctx) {
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_D)
static int d(void *ctx) {
        tail_call_static(ctx, cilium_calls_test, TAIL_E);
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_C)
static int c(void *ctx) {
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_B)
static int b(void *ctx) {
        tail_call_static(ctx, cilium_calls_test, TAIL_C);
        return 0;
}


__section_tail(CILIUM_MAP_CALLS, TAIL_A)
static int a(void *ctx) {
        if (global_var == 0x01) {
                tail_call_static(ctx, cilium_calls_test, TAIL_B);
        } else {
                tail_call_static(ctx, cilium_calls_test, TAIL_C);
        }

        return 0;
}

__section("tc")
static int cil_entry(void *ctx) {
        tail_call_static(ctx, cilium_calls_test, TAIL_A);
        return 0;
}
