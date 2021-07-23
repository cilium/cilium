# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 Authors of Cilium

# 1 Add [GENERATED FROM bpf/helpers.h] at the front.
# 2 Delete lines start with [#ifndef BPF_] and ends with [#endif].
# 3 Delete lines start with [#if __ctx_is] and ends with [#endif].
# 4 Replace ["compiler.h"] by [<bpf/compiler.h>].
# 5 Delete lines containing [ctx/ctx.h].
# 6 Replace [__BPF_HELPERS] by [__MOCK_HELPERS].
# 7 Remove [static].
# 8&9 Restruct the functions to normal styles.
# 10 Remove [_printf(1, 3)] in function trace_printk.
# 11 Remove remappings.

1 s|^|/\* GENERATED FROM bpf/helpers\.h \*/\n|;
/#ifndef BPF_/,/#endif/d;
/#if __ctx_is/,/#endif/d;
s|"compiler\.h"|<bpf/compiler\.h>|g;
/ctx\/ctx.h/d;
s/__BPF_HELPERS\(.*__\)/__MOCK_HELPERS\1/g;
s/static //g;
s/BPF_\w*(\(\w*\), /\1(/g;
s/BPF_\w*(\(\w*\)/\1(/g;
s/__printf(.*) //g;
/ =/{ N; s/ =.*;/;/ };
