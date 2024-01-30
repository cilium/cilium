#include <bpf/ctx/skb.h>
#include <ep_config.h>
#include <node_config.h>

#define __NR_CPUS__ 1
#include "lib/maps.h"

#define TAIL_A 1
#define TAIL_B 2
#define TAIL_C 3
#define TAIL_D 4
#define TAIL_E 5

__section_tail(CILIUM_MAP_CALLS, TAIL_E)
static int e(struct __sk_buff *ctx) {
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_D)
static int d(struct __sk_buff *ctx) {
        tail_call_static(ctx, CALLS_MAP, TAIL_E);
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_C)
static int c(struct __sk_buff *ctx) {
        return 0;
}

__section_tail(CILIUM_MAP_CALLS, TAIL_B)
static int b(struct __sk_buff *ctx) {
        tail_call_static(ctx, CALLS_MAP, TAIL_C);
        return 0;
}


__section_tail(CILIUM_MAP_CALLS, TAIL_A)
static int a(struct __sk_buff *ctx) {
        void *data = (void*)(long long)ctx->data;
        void *data_end = (void*)(long long)ctx->data_end;

        if (data + 1 > data_end)
                return 0;

        if (((char *)data)[0] == 0x01) {
                tail_call_static(ctx, CALLS_MAP, TAIL_B);
        } else {
                tail_call_static(ctx, CALLS_MAP, TAIL_C);
        }

        return 0;
}

__section("tc")
static int cil_entry(struct __sk_buff *ctx) {
        tail_call_static(ctx, CALLS_MAP, TAIL_A);
        return 0;
}
