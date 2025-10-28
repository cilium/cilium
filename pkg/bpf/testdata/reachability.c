#include <bpf/ctx/skb.h>
#include "common.h"

#include <lib/static_data.h>

/* Emit a symbol sentinel and an access to it. Can be checked using
 * asm.Instruction.Reference(). */
#define SYMBOL(name) { void * name; asm volatile("%0 = " __stringify(name) :"=r"(name)); }

DECLARE_CONFIG(bool, sym_a, "Make sym_a reachable")
DECLARE_CONFIG(__u64, sym_b, "Make sym_b reachable if value >= max uint32, requiring 64-bit reg-reg comparison")
DECLARE_CONFIG(struct { __u8 _pad; bool sym_c; __u32 sym_d; }, sym_cd, "Make sym_c and sym_d reachable")
DECLARE_CONFIG(__s64, sym_e, "Make sym_e reachable if value is negative")

__section("tc")
static int entry() {
        if (CONFIG(sym_a))
                SYMBOL(sym_a);

        if (CONFIG(sym_b) >= 1LL<<32)
                SYMBOL(sym_b);

        if (CONFIG(sym_cd).sym_c)
                SYMBOL(sym_c);

        if (CONFIG(sym_cd).sym_d == 1234)
                SYMBOL(sym_d);

        if (CONFIG(sym_e) < 0)
                SYMBOL(sym_e);

        return 0;
}
