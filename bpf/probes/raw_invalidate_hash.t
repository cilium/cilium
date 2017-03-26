/* Tests for availability of kernel commits (4.9+):
 *
 * 7a4b28c6cc9f ("bpf: add helper to invalidate hash")
 */
	{
		.emits	= "HAVE_SET_HASH_INVALID",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_EMIT_CALL(BPF_FUNC_set_hash_invalid),
			BPF_EXIT_INSN(),
		},
		/* No warning required to the user. */
	},
