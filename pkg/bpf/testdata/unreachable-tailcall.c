#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

#include <bpf/tailcall.h>
#include <lib/tailcall.h>

DECLARE_CONFIG(bool, use_tail_b, "Use tailcall B or C")

#define TAIL_A 0
#define TAIL_B 1
#define TAIL_C 2
#define TAIL_D 3
#define TAIL_E 4

__declare_tail(TAIL_E)
static int e(void *ctx) {
        return 0;
}

__declare_tail(TAIL_D)
static int d(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_E);
        return 0;
}

__declare_tail(TAIL_C)
static int c(void *ctx) {
        return 0;
}

__declare_tail(TAIL_B)
static int b(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_C);
        return 0;
}

__declare_tail(TAIL_A)
static int a(void *ctx) {
        if (CONFIG(use_tail_b)) {
                tail_call_static(ctx, cilium_calls, TAIL_B);
        } else {
                tail_call_static(ctx, cilium_calls, TAIL_C);
        }

        return 0;
}

__section_entry
static int cil_entry(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_A);

        // Technically unreachable, but makes sure all paths are visited by the
        // pruner. In real-world code, tail calls are often invoked
        // conditionally, e.g. for error reporting or v4/v6 handling depending
        // on the packet, so the search can't stop after the first tail call.
        tail_call_static(ctx, cilium_calls, TAIL_E);
        return 0;
}
