/* Tests for availability of kernel commits (4.17+):
 *
 * 87f5fc7e48dd ("bpf: Provide helper to do forwarding lookups in kernel FIB table")
 */
	{
		.emits	= "HAVE_FIB_LOOKUP",
		.type	= BPF_PROG_TYPE_SCHED_CLS,
		.insns	= {
			BPF_ALU64_REG(BPF_MOV, BPF_REG_6, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_6, 0, 0xcafe),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
			BPF_MOV64_IMM(BPF_REG_3, 2),
			BPF_MOV64_IMM(BPF_REG_4, 0),
			BPF_MOV64_IMM(BPF_REG_5, 0),
			BPF_EMIT_CALL(BPF_FUNC_fib_lookup),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, 0),
			BPF_EXIT_INSN(),
		},
	},
