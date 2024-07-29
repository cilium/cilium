/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#pragma once

#ifndef BPF_TEST
#define __MAGIC_FILE__ (__u8)__id_for_file(__FILE_NAME__)
#define __MAGIC_LINE__ __LINE__
#else
/* bpf tests assert that metrics get updated by performing a map lookup.
 * This cannot work if the metrics key has dynamic components like line/file
 * info, so disable this during tests.
 */
#define __MAGIC_FILE__ 0
#define __MAGIC_LINE__ 0
#endif

#define _strcase_(id, known_name) do {			\
	if (!__builtin_strcmp(header_name, known_name))	\
		return id;				\
	} while (0)

/*
 * __id_for_file is used by __MAGIC_FILE__ to encode source file information in
 * drop notifications and forward/drop metrics. It must be inlined, otherwise
 * clang won't translate this to a constexpr.
 *
 * The following list of files is static, but it is validated during build with
 * the pkg/datapath/loader/check-sources.sh tool.
 */
static __always_inline int
__id_for_file(const char *const header_name)
{
	/* @@ source files list begin */

	/* source files from bpf/ */
	_strcase_(1, "bpf_host.c");
	_strcase_(2, "bpf_lxc.c");
	_strcase_(3, "bpf_overlay.c");
	_strcase_(4, "bpf_xdp.c");
	_strcase_(5, "bpf_sock.c");
	_strcase_(6, "bpf_network.c");
	_strcase_(7, "bpf_wireguard.c");

	/* header files from bpf/lib/ */
	_strcase_(101, "arp.h");
	_strcase_(102, "drop.h");
	_strcase_(103, "srv6.h");
	_strcase_(104, "icmp6.h");
	_strcase_(105, "nodeport.h");
	_strcase_(106, "lb.h");
	_strcase_(107, "mcast.h");
	_strcase_(108, "ipv4.h");
	_strcase_(109, "conntrack.h");
	_strcase_(110, "l3.h");
	_strcase_(111, "trace.h");
	_strcase_(112, "encap.h");
	_strcase_(113, "encrypt.h");

	/* @@ source files list end */

	return 0;
}

#undef _strcase_
