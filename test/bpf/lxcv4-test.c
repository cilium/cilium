/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// source file for lxcv4_test.h.
// It contains contains main functions to run test functions lxcv4_test.h.
// It is used to perform unit test on functions in bpf_lxc.c.

#include "tests/lxcv4_test.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}


int main(int argc, char *argv[])
{
    test_handle_ipv4_from_lxc();
    return 0;
}
