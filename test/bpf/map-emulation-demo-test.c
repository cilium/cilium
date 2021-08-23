/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Authors of Cilium */

// source file for map_emulation_demo.h.
// It contains contains main functions to run test functions in map_emulation_demo.h.
// It is used to perform unit test on functions in map_emulation_demo.h.

#include "tests/map_emulation_demo_test.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}


int main(int argc, char *argv[])
{
    test_snat_v4_new_mapping();
    return 0;
}
