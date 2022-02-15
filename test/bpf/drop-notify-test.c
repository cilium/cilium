// SPDX-License-Identifier: GPL-2.0 
/* Copyright (C) 2021 Authors of Cilium */

// source file for drop_notify_test.h.
// It contains contains main functions to run test functions drop_notify_test.h.
// It is used to perform unit test on functions in drop.h.

#include "tests/drop_notify_test.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}


int main(int argc, char *argv[])
{
  test_send_drop_notify();
  return 0;
}
