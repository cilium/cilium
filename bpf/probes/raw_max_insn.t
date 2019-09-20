/* Tests for availability of kernel commits (5.3):
 *
 * c04c0d2b968a ("bpf: increase complexity limit and maximum program size")
 */
	{
		.emits		= "HAVE_LARGE_INSN_LIMIT",
		.type		= BPF_PROG_TYPE_SCHED_CLS,
		.insns		= {
			BPF_MOV64_IMM(BPF_REG_0, 1), // insn-repeat:4128
			BPF_EXIT_INSN(),
		},
		/* No warning required to the user. */
	},
