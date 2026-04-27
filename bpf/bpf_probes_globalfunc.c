// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* This probe lives in its own translation unit (rather than bpf_probes.c)
 * because it is expected to fail to load on kernels with incomplete vmlinux
 * BTF. Sharing bpf_probes.c would cause the entire probes object to fail
 * loading on those kernels, breaking unrelated feature detection.
 */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <lib/static_data.h>

/* The pair below detects whether the running kernel can verify a BPF-to-BPF
 * call whose argument is a program context pointer (e.g. struct __sk_buff *).
 *
 * The verifier validates such arguments via btf_validate_prog_ctx_type(), which
 * dereferences the bpf_ctx_convert anchor in vmlinux BTF. On kernels whose
 * vmlinux BTF was built without that anchor (observed on some downstream
 * builds, e.g. Raspberry Pi OS arm64 in cilium/cilium#45224), the load fails
 * with "btf_vmlinux is malformed" / "Caller passes invalid args into func#1".
 *
 * If this probe loads successfully, the kernel can verify global functions
 * with ctx arguments, and the datapath may use that linkage to reduce
 * verifier complexity. Otherwise such helpers must remain __always_inline.
 */
__noinline __weak int
probe_global_func_ctx_arg_callee(struct __ctx_buff *ctx __maybe_unused)
{
	return 0;
}

__section_entry
int probe_global_func_ctx_arg(struct __ctx_buff *ctx)
{
	return probe_global_func_ctx_arg_callee(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
