# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 Authors of Cilium

# 1 Add [GENERATED FROM bpf/helpers_skb.h] at the front.
# 2 Delete lines start with [#ifndef BPF_] and ends with [#endif].
# 3 Delete lines start with [#if __ctx_is] and ends with [#endif].
# 4 Replace ["features_skb.h"] by [<bpf/features_skb.h>].
# 5 Replace ["compiler.h"] by [<bpf/compiler.h>].
# 6 Delete lines containing [helpers.h].
# 7 Replace [__BPF_HELPERS] by [__MOCK_HELPERS].
# 8 Remove [static].
# 9&10 Restruct the functions to normal styles.
# 11 Remove remappings.

1 s|^|/\* GENERATED FROM bpf/helpers_skb\.h \*/\n|;
/#ifndef BPF_/,/#endif/d;
/#if __ctx_is/,/#endif/d;
s|"features_skb\.h"|<bpf/features_skb\.h>|g;
s|"compiler\.h"|<bpf/compiler\.h>|g;
/"helpers\.h"/d;
s/__BPF_HELPERS\(.*__\)/__MOCK_HELPERS\1/g;
s/static //g;
s/BPF_\w*(\(\w*\), /\1(/g;
s/BPF_\w*(\(\w*\)/\1(/g;
/ =/{ N; s/ =.*;/;/ };
