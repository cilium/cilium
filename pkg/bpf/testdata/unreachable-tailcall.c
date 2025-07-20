#include <bpf/ctx/skb.h>
#include "common.h"

#include <bpf/tailcall.h>
#include <lib/tailcall.h>

volatile const int global_var = 0;

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
        if (global_var == 0x01) {
                tail_call_static(ctx, cilium_calls, TAIL_B);
        } else {
                tail_call_static(ctx, cilium_calls, TAIL_C);
        }

        return 0;
}

__section_entry
static int cil_entry(void *ctx) {
        tail_call_static(ctx, cilium_calls, TAIL_A);
        return 0;
}
