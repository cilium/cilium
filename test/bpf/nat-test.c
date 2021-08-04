/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// source file for nat_test.h.
// It contains contains main functions to run test functions nat_test.h.
// It is used to perform unit test on functions in nat.h.

#include "tests/nat_test.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}


int main(int argc, char *argv[])
{
    test_snat_v4_track_local();
    return 0;
}
