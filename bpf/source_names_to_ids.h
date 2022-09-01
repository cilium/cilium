/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#ifndef HEADER_NAMES_TO_IDS_H_
#define HEADER_NAMES_TO_IDS_H_

#define _strcase_(id, known_name) do {			\
	if (!__builtin_strcmp(header_name, known_name))	\
		return id;				\
	} while (0)

/*
 * The __source_file_name_to_id function is used inside lib/drop.h to encode
 * source file information with drop info messages. It must be always inlined,
 * otherwise clang won't translate this to a constexpr.
 *
 * The following list of files is static, but it is validated during build with
 * the pkg/datapath/loader/check-sources.sh tool.
 */
static __always_inline int
__source_file_name_to_id(const char *const header_name)
{
	/* source files from bpf/ */
	_strcase_(1, "bpf_host.c");
	_strcase_(2, "bpf_lxc.c");
	_strcase_(3, "bpf_overlay.c");
	_strcase_(4, "bpf_xdp.c");

	/* header files from bpf/lib/ */
	_strcase_(101, "arp.h");
	_strcase_(102, "drop.h");
	_strcase_(103, "egress_policies.h");
	_strcase_(104, "icmp6.h");
	_strcase_(105, "nodeport.h");

	return 0;
}

#undef _strcase_

#endif /* HEADER_NAMES_TO_IDS_H_ */
