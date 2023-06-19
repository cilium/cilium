/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define CLIENT_PORT __bpf_htons(111)

enum egressgw_test {
	TEST_SNAT1                    = 0,
	TEST_SNAT2                    = 1,
	TEST_SNAT_EXCL_CIDR           = 2,
	TEST_REDIRECT                 = 3,
	TEST_REDIRECT_EXCL_CIDR       = 4,
	TEST_REDIRECT_SKIP_NO_GATEWAY = 5,
	TEST_XDP_REPLY                = 6,
};

static __always_inline __be16 client_port(enum egressgw_test t)
{
	return CLIENT_PORT + (__be16)t;
}
