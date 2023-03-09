// SPDX-License-Identifier: GPL-2.0
// Copyright Authors of Cilium

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <assert.h>
#include <stdlib.h>

#include "lib/utils.h"

#include "lib/common.h"

#include "node_config.h"

#define HAVE_LARGE_INSN_LIMIT

#define htonl bpf_htonl
#define ntohl bpf_ntohl

#include "tests/builtin_test.h"

int main(int argc, char *argv[])
{
	srandom(0x61C88647);

	test___builtin_memzero();
	test___builtin_memcpy();
	test___builtin_memcmp();
	test___builtin_memmove();

	return 0;
}
