/* Tests for availability of kernel commits (4.9+):
 *
 * 5293efe62df8 ("bpf: add bpf_skb_change_tail helper")
 */
	{
		.emits	= "HAVE_SKB_CHANGE_TAIL",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_MOV64_IMM(BPF_REG_2, 0),
			BPF_MOV64_IMM(BPF_REG_3, 0),
			BPF_EMIT_CALL(BPF_FUNC_skb_change_tail),
			BPF_EXIT_INSN(),
		},
		.warn = "Kernel does not support bpf_skb_change_tail() helper. "
			"Therefore, cilium does not support sending ICMPv6 time "
			"exceeded notifications. Recommendation is to run 4.9+ "
			"kernels.",
	},
