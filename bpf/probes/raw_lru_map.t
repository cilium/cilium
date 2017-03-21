/* Tests for availability of kernel commits (4.10+):
 *
 * 961578b63474 ("bpf: Add percpu LRU list")
 * 3a08c2fd7634 ("bpf: LRU List")
 */
	{
		.emits	= "HAVE_LRU_MAP_TYPE",
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
				.type		= BPF_MAP_TYPE_LRU_HASH,
				.size_key	= 8,
				.size_val	= 8,
			},
		},
		.warn = "Your kernel doesn't support LRU maps for BPF, thus "
			"switching back to using hash table for the cilium "
			"connection tracker. Recommendation is to run 4.10+ "
			"kernels.",
	},
