/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// source file for sock_test.h.
// It contains contains main functions to run test functions sock_test.h.
// It is used to perform unit test on functions in bpf_sock.c.

#include "tests/sockv4_test.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}


int main(int argc, char *argv[])
{
    test___sock4_xlate_fwd();
    return 0;
}
