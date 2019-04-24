/* Tests for availability of kernel commits (4.19+):
 *
 * d692f1138a4b ("bpf: Support bpf_get_socket_cookie in more prog types")
 */
	{
		.emits		= "HAVE_GET_SOCK_COOKIE",
		.type		= BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
		.attach_type	= BPF_CGROUP_INET4_CONNECT,
		.insns		= {
			BPF_EMIT_CALL(BPF_FUNC_get_socket_cookie),
			BPF_MOV64_IMM(BPF_REG_0, 1),
			BPF_EXIT_INSN(),
		},
		/* No warning required to the user. */
	},
