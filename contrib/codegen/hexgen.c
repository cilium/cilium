#include <stdio.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include "hexgen.h"

int main(void)
{
	struct bpf_insn	insns[] = {
		BPF_LD_MAP_FD(BPF_REG_2, 0xebebebeb),
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_tail_call),
		BPF_MOV64_IMM(BPF_REG_0, TC_ACT_OK),
		BPF_EXIT_INSN(),
	};
	__u8 *raw = (void *)insns;
	int i;

	for (i = 1; i <= sizeof(insns); i++) {
		printf("0x%02x, ", raw[i - 1]);
		if (i % 8 == 0)
			printf("\n");
	}
	printf("\n");
	return 0;
}
