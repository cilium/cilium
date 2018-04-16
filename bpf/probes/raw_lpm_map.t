/* Tests for availability of kernel commits (4.11+):
 *
 * b95a5c4db09b ("bpf: add a longest prefix match trie map implementation")
 */
	{
		.emits	= "HAVE_LPM_MAP_TYPE",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, 0, 0),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		},
		.fixup_map = {
			{
				.off		= 3,
				.type		= BPF_MAP_TYPE_LPM_TRIE,
				.size_key	= 8,
				.size_val	= 4,
				.flags		= BPF_F_NO_PREALLOC,
			},
		},
		.warn = "Your kernel doesn't support LPM trie maps for BPF, "
		        "thus switching back to using hash table for CIDR "
			"policies. Recommendation is to run 4.11+ kernels.",
	},
