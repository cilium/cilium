/* Tests for availability of kernel commits (4.9/stable, 4.10+):
 *
 * 6760bf2ddde8 ("bpf: fix mark_reg_unknown_value for spilled regs on map value marking")
 * a08dd0da5307 ("bpf: fix regression on verifier pruning wrt map lookups")
 * d2a4dd37f6b4 ("bpf: fix state equivalence")
 * 57a09bf0a416 ("bpf: Detect identical PTR_TO_MAP_VALUE_OR_NULL registers")
 */
	{
		.emits	= "HAVE_MARK_MAP_VALS",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -152),
			BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
			BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_1, 0),
			BPF_ST_MEM(BPF_DW, BPF_REG_3, 0, 42),
			BPF_EXIT_INSN(),
		},
		.fixup_map = {
			{
				.off		= 3,
				.type		= BPF_MAP_TYPE_HASH,
				.size_key	= 8,
				.size_val	= 8,
			},
		},
		.warn = "Verifier is too old to detect identical registers "
			"with map value after bpf_map_lookup_elem(). Some "
			"clang versions might generate code that spills such "
			"registers to stack before a NULL test. Recommendation "
			"is to run 4.10+ kernels.",
			/* Note: Expected to be in 4.9.17 or 4.9.18. Once that
			 * is released, we can upgrade the warning message.
			 */
	},
