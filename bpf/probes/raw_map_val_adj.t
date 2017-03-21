/* Tests for availability of kernel commits (4.9+):
 *
 * d2a4dd37f6b4 ("bpf: fix state equivalence") [** will appear in 4.9 stable]
 * e2d2afe15ed4 ("bpf: fix states equal logic for varlen access")
 * f23cc643f9ba ("bpf: fix range arithmetic for bpf map access")
 * 484611357c19 ("bpf: allow access into map value arrays")
 */
	{
		.emits	= "HAVE_MAP_VAL_ADJ",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 6),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 8),
			BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JGT, BPF_REG_3, 1, 2),
			BPF_MOV64_IMM(BPF_REG_0, 1),
			BPF_EXIT_INSN(),
			BPF_MOV64_IMM(BPF_REG_0, 2),
			BPF_EXIT_INSN(),
		},
		.fixup_map = {
			{
				.off		= 3,
				.type		= BPF_MAP_TYPE_HASH,
				.size_key	= 8,
				.size_val	= 16,
			},
		},
		.warn = "Verifier is too old to detect dynamic map value access "
			"after bpf_map_lookup_elem(). Recommendation is to run 4.9+ "
			"kernels.",
	},
