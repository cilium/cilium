/* ==========================================
    Unity Project - A Test Framework for C
    Copyright (c) 2007-21 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
========================================== */

#ifndef UNITY_FRAMEWORK_H
#define UNITY_FRAMEWORK_H
#define UNITY

#define UNITY_VERSION_MAJOR    2
#define UNITY_VERSION_MINOR    5
#define UNITY_VERSION_BUILD    4
#define UNITY_VERSION          ((UNITY_VERSION_MAJOR << 16) | (UNITY_VERSION_MINOR << 8) | UNITY_VERSION_BUILD)

#ifdef __cplusplus
extern "C"
{
#endif

#include "unity_internals.h"

/*-------------------------------------------------------
 * Test Setup / Teardown
 *-------------------------------------------------------*/

/* These functions are intended to be called before and after each test.
 * If using unity directly, these will need to be provided for each test
 * executable built. If you are using the test runner generator and/or
 * Ceedling, these are optional. */
void setUp(void);
void tearDown(void);

/* These functions are intended to be called at the beginning and end of an
 * entire test suite.  suiteTearDown() is passed the number of tests that
 * failed, and its return value becomes the exit code of main(). If using
 * Unity directly, you're in charge of calling these if they are desired.
 * If using Ceedling or the test runner generator, these will be called
 * automatically if they exist. */
void suiteSetUp(void);
int suiteTearDown(int num_failures);

/*-------------------------------------------------------
 * Test Reset and Verify
 *-------------------------------------------------------*/

/* These functions are intended to be called before during tests in order
 * to support complex test loops, etc. Both are NOT built into Unity. Instead
 * the test runner generator will create them. resetTest will run teardown and
 * setup again, verifying any end-of-test needs between. verifyTest will only
 * run the verification. */
void resetTest(void);
void verifyTest(void);

/*-------------------------------------------------------
 * Configuration Options
 *-------------------------------------------------------
 * All options described below should be passed as a compiler flag to all files using Unity. If you must add #defines, place them BEFORE the #include above.

 * Integers/longs/pointers
 *     - Unity attempts to automatically discover your integer sizes
 *       - define UNITY_EXCLUDE_STDINT_H to stop attempting to look in <stdint.h>
 *       - define UNITY_EXCLUDE_LIMITS_H to stop attempting to look in <limits.h>
 *     - If you cannot use the automatic methods above, you can force Unity by using these options:
 *       - define UNITY_SUPPORT_64
 *       - set UNITY_INT_WIDTH
 *       - set UNITY_LONG_WIDTH
 *       - set UNITY_POINTER_WIDTH

 * Floats
 *     - define UNITY_EXCLUDE_FLOAT to disallow floating point comparisons
 *     - define UNITY_FLOAT_PRECISION to specify the precision to use when doing TEST_ASSERT_EQUAL_FLOAT
 *     - define UNITY_FLOAT_TYPE to specify doubles instead of single precision floats
 *     - define UNITY_INCLUDE_DOUBLE to allow double floating point comparisons
 *     - define UNITY_EXCLUDE_DOUBLE to disallow double floating point comparisons (default)
 *     - define UNITY_DOUBLE_PRECISION to specify the precision to use when doing TEST_ASSERT_EQUAL_DOUBLE
 *     - define UNITY_DOUBLE_TYPE to specify something other than double
 *     - define UNITY_EXCLUDE_FLOAT_PRINT to trim binary size, won't print floating point values in errors

 * Output
 *     - by default, Unity prints to standard out with putchar.  define UNITY_OUTPUT_CHAR(a) with a different function if desired
 *     - define UNITY_DIFFERENTIATE_FINAL_FAIL to print FAILED (vs. FAIL) at test end summary - for automated search for failure

 * Optimization
 *     - by default, line numbers are stored in unsigned shorts.  Define UNITY_LINE_TYPE with a different type if your files are huge
 *     - by default, test and failure counters are unsigned shorts.  Define UNITY_COUNTER_TYPE with a different type if you want to save space or have more than 65535 Tests.

 * Test Cases
 *     - define UNITY_SUPPORT_TEST_CASES to include the TEST_CASE macro, though really it's mostly about the runner generator script

 * Parameterized Tests
 *     - you'll want to create a define of TEST_CASE(...) which basically evaluates to nothing

 * Tests with Arguments
 *     - you'll want to define UNITY_USE_COMMAND_LINE_ARGS if you have the test runner passing arguments to Unity

 *-------------------------------------------------------
 * Basic Fail and Ignore
 *-------------------------------------------------------*/

#define TEST_FAIL_MESSAGE(message)                                                                 UNITY_TEST_FAIL(__LINE__, (message))
#define TEST_FAIL()                                                                                UNITY_TEST_FAIL(__LINE__, NULL)
#define TEST_IGNORE_MESSAGE(message)                                                               UNITY_TEST_IGNORE(__LINE__, (message))
#define TEST_IGNORE()                                                                              UNITY_TEST_IGNORE(__LINE__, NULL)
#define TEST_MESSAGE(message)                                                                      UnityMessage((message), __LINE__)
#define TEST_ONLY()
#ifdef UNITY_INCLUDE_PRINT_FORMATTED
#define TEST_PRINTF(message, ...)                                                                  UnityPrintF(__LINE__, (message), __VA_ARGS__)
#endif

/* It is not necessary for you to call PASS. A PASS condition is assumed if nothing fails.
 * This method allows you to abort a test immediately with a PASS state, ignoring the remainder of the test. */
#define TEST_PASS()                                                                                TEST_ABORT()
#define TEST_PASS_MESSAGE(message)                                                                 do { UnityMessage((message), __LINE__); TEST_ABORT(); } while(0)

/* This macro does nothing, but it is useful for build tools (like Ceedling) to make use of this to figure out
 * which files should be linked to in order to perform a test. Use it like TEST_FILE("sandwiches.c") */
#define TEST_FILE(a)

/*-------------------------------------------------------
 * Test Asserts (simple)
 *-------------------------------------------------------*/

/* Boolean */
#define TEST_ASSERT(condition)                                                                     UNITY_TEST_ASSERT(       (condition), __LINE__, " Expression Evaluated To FALSE")
#define TEST_ASSERT_TRUE(condition)                                                                UNITY_TEST_ASSERT(       (condition), __LINE__, " Expected TRUE Was FALSE")
#define TEST_ASSERT_UNLESS(condition)                                                              UNITY_TEST_ASSERT(      !(condition), __LINE__, " Expression Evaluated To TRUE")
#define TEST_ASSERT_FALSE(condition)                                                               UNITY_TEST_ASSERT(      !(condition), __LINE__, " Expected FALSE Was TRUE")
#define TEST_ASSERT_NULL(pointer)                                                                  UNITY_TEST_ASSERT_NULL(    (pointer), __LINE__, " Expected NULL")
#define TEST_ASSERT_NOT_NULL(pointer)                                                              UNITY_TEST_ASSERT_NOT_NULL((pointer), __LINE__, " Expected Non-NULL")
#define TEST_ASSERT_EMPTY(pointer)                                                                 UNITY_TEST_ASSERT_EMPTY(    (pointer), __LINE__, " Expected Empty")
#define TEST_ASSERT_NOT_EMPTY(pointer)                                                             UNITY_TEST_ASSERT_NOT_EMPTY((pointer), __LINE__, " Expected Non-Empty")

/* Integers (of all sizes) */
#define TEST_ASSERT_EQUAL_INT(expected, actual)                                                    UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT8(expected, actual)                                                   UNITY_TEST_ASSERT_EQUAL_INT8((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT16(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_INT16((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT32(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_INT32((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT64(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_INT64((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT(expected, actual)                                                   UNITY_TEST_ASSERT_EQUAL_UINT( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT8(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_UINT8( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT16(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_UINT16( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT32(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_UINT32( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT64(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_UINT64( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_size_t(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_UINT((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX(expected, actual)                                                    UNITY_TEST_ASSERT_EQUAL_HEX32((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX8(expected, actual)                                                   UNITY_TEST_ASSERT_EQUAL_HEX8( (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX16(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_HEX16((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX32(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_HEX32((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX64(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_HEX64((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_CHAR(expected, actual)                                                   UNITY_TEST_ASSERT_EQUAL_CHAR((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_BITS(mask, expected, actual)                                                   UNITY_TEST_ASSERT_BITS((mask), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_BITS_HIGH(mask, actual)                                                        UNITY_TEST_ASSERT_BITS((mask), (UNITY_UINT)(-1), (actual), __LINE__, NULL)
#define TEST_ASSERT_BITS_LOW(mask, actual)                                                         UNITY_TEST_ASSERT_BITS((mask), (UNITY_UINT)(0), (actual), __LINE__, NULL)
#define TEST_ASSERT_BIT_HIGH(bit, actual)                                                          UNITY_TEST_ASSERT_BITS(((UNITY_UINT)1 << (bit)), (UNITY_UINT)(-1), (actual), __LINE__, NULL)
#define TEST_ASSERT_BIT_LOW(bit, actual)                                                           UNITY_TEST_ASSERT_BITS(((UNITY_UINT)1 << (bit)), (UNITY_UINT)(0), (actual), __LINE__, NULL)

/* Integer Not Equal To (of all sizes) */
#define TEST_ASSERT_NOT_EQUAL_INT(threshold, actual)                                               UNITY_TEST_ASSERT_NOT_EQUAL_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_INT8(threshold, actual)                                              UNITY_TEST_ASSERT_NOT_EQUAL_INT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_INT16(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_INT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_INT32(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_INT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_INT64(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_INT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_UINT(threshold, actual)                                              UNITY_TEST_ASSERT_NOT_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_UINT8(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_UINT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_UINT16(threshold, actual)                                            UNITY_TEST_ASSERT_NOT_EQUAL_UINT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_UINT32(threshold, actual)                                            UNITY_TEST_ASSERT_NOT_EQUAL_UINT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_UINT64(threshold, actual)                                            UNITY_TEST_ASSERT_NOT_EQUAL_UINT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_size_t(threshold, actual)                                            UNITY_TEST_ASSERT_NOT_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_HEX8(threshold, actual)                                              UNITY_TEST_ASSERT_NOT_EQUAL_HEX8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_HEX16(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_HEX16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_HEX32(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_HEX32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_HEX64(threshold, actual)                                             UNITY_TEST_ASSERT_NOT_EQUAL_HEX64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL_CHAR(threshold, actual)                                              UNITY_TEST_ASSERT_NOT_EQUAL_CHAR((threshold), (actual), __LINE__, NULL)

/* Integer Greater Than/ Less Than (of all sizes) */
#define TEST_ASSERT_GREATER_THAN(threshold, actual)                                                UNITY_TEST_ASSERT_GREATER_THAN_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_INT(threshold, actual)                                            UNITY_TEST_ASSERT_GREATER_THAN_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_INT8(threshold, actual)                                           UNITY_TEST_ASSERT_GREATER_THAN_INT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_INT16(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_INT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_INT32(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_INT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_INT64(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_INT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_UINT(threshold, actual)                                           UNITY_TEST_ASSERT_GREATER_THAN_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_UINT8(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_UINT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_UINT16(threshold, actual)                                         UNITY_TEST_ASSERT_GREATER_THAN_UINT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_UINT32(threshold, actual)                                         UNITY_TEST_ASSERT_GREATER_THAN_UINT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_UINT64(threshold, actual)                                         UNITY_TEST_ASSERT_GREATER_THAN_UINT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_size_t(threshold, actual)                                         UNITY_TEST_ASSERT_GREATER_THAN_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_HEX8(threshold, actual)                                           UNITY_TEST_ASSERT_GREATER_THAN_HEX8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_HEX16(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_HEX16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_HEX32(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_HEX32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_HEX64(threshold, actual)                                          UNITY_TEST_ASSERT_GREATER_THAN_HEX64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_THAN_CHAR(threshold, actual)                                           UNITY_TEST_ASSERT_GREATER_THAN_CHAR((threshold), (actual), __LINE__, NULL)

#define TEST_ASSERT_LESS_THAN(threshold, actual)                                                   UNITY_TEST_ASSERT_SMALLER_THAN_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_INT(threshold, actual)                                               UNITY_TEST_ASSERT_SMALLER_THAN_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_INT8(threshold, actual)                                              UNITY_TEST_ASSERT_SMALLER_THAN_INT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_INT16(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_INT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_INT32(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_INT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_INT64(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_INT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_UINT(threshold, actual)                                              UNITY_TEST_ASSERT_SMALLER_THAN_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_UINT8(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_UINT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_UINT16(threshold, actual)                                            UNITY_TEST_ASSERT_SMALLER_THAN_UINT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_UINT32(threshold, actual)                                            UNITY_TEST_ASSERT_SMALLER_THAN_UINT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_UINT64(threshold, actual)                                            UNITY_TEST_ASSERT_SMALLER_THAN_UINT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_size_t(threshold, actual)                                            UNITY_TEST_ASSERT_SMALLER_THAN_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_HEX8(threshold, actual)                                              UNITY_TEST_ASSERT_SMALLER_THAN_HEX8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_HEX16(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_HEX16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_HEX32(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_HEX32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_HEX64(threshold, actual)                                             UNITY_TEST_ASSERT_SMALLER_THAN_HEX64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_THAN_CHAR(threshold, actual)                                              UNITY_TEST_ASSERT_SMALLER_THAN_CHAR((threshold), (actual), __LINE__, NULL)

#define TEST_ASSERT_GREATER_OR_EQUAL(threshold, actual)                                            UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_INT(threshold, actual)                                        UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_INT8(threshold, actual)                                       UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_INT16(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_INT32(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_INT64(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT(threshold, actual)                                       UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT8(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT16(threshold, actual)                                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT32(threshold, actual)                                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT64(threshold, actual)                                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_size_t(threshold, actual)                                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX8(threshold, actual)                                       UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX16(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX32(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX64(threshold, actual)                                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_GREATER_OR_EQUAL_CHAR(threshold, actual)                                       UNITY_TEST_ASSERT_GREATER_OR_EQUAL_CHAR((threshold), (actual), __LINE__, NULL)

#define TEST_ASSERT_LESS_OR_EQUAL(threshold, actual)                                               UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_INT(threshold, actual)                                           UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_INT8(threshold, actual)                                          UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_INT16(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_INT32(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_INT64(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_UINT(threshold, actual)                                          UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_UINT8(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_UINT16(threshold, actual)                                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_UINT32(threshold, actual)                                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_UINT64(threshold, actual)                                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_size_t(threshold, actual)                                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_HEX8(threshold, actual)                                          UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX8((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_HEX16(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX16((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_HEX32(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX32((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_HEX64(threshold, actual)                                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX64((threshold), (actual), __LINE__, NULL)
#define TEST_ASSERT_LESS_OR_EQUAL_CHAR(threshold, actual)                                          UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_CHAR((threshold), (actual), __LINE__, NULL)

/* Integer Ranges (of all sizes) */
#define TEST_ASSERT_INT_WITHIN(delta, expected, actual)                                            UNITY_TEST_ASSERT_INT_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_INT8_WITHIN(delta, expected, actual)                                           UNITY_TEST_ASSERT_INT8_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_INT16_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_INT16_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_INT32_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_INT32_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_INT64_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_INT64_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_UINT_WITHIN(delta, expected, actual)                                           UNITY_TEST_ASSERT_UINT_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_UINT8_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_UINT8_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_UINT16_WITHIN(delta, expected, actual)                                         UNITY_TEST_ASSERT_UINT16_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_UINT32_WITHIN(delta, expected, actual)                                         UNITY_TEST_ASSERT_UINT32_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_UINT64_WITHIN(delta, expected, actual)                                         UNITY_TEST_ASSERT_UINT64_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_size_t_WITHIN(delta, expected, actual)                                         UNITY_TEST_ASSERT_UINT_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_HEX_WITHIN(delta, expected, actual)                                            UNITY_TEST_ASSERT_HEX32_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_HEX8_WITHIN(delta, expected, actual)                                           UNITY_TEST_ASSERT_HEX8_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_HEX16_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_HEX16_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_HEX32_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_HEX32_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_HEX64_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_HEX64_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_CHAR_WITHIN(delta, expected, actual)                                           UNITY_TEST_ASSERT_CHAR_WITHIN((delta), (expected), (actual), __LINE__, NULL)

/* Integer Array Ranges (of all sizes) */
#define TEST_ASSERT_INT_ARRAY_WITHIN(delta, expected, actual, num_elements)                        UNITY_TEST_ASSERT_INT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_INT8_ARRAY_WITHIN(delta, expected, actual, num_elements)                       UNITY_TEST_ASSERT_INT8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_INT16_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_INT16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_INT32_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_INT32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_INT64_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_INT64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_UINT_ARRAY_WITHIN(delta, expected, actual, num_elements)                       UNITY_TEST_ASSERT_UINT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_UINT8_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_UINT8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_UINT16_ARRAY_WITHIN(delta, expected, actual, num_elements)                     UNITY_TEST_ASSERT_UINT16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_UINT32_ARRAY_WITHIN(delta, expected, actual, num_elements)                     UNITY_TEST_ASSERT_UINT32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_UINT64_ARRAY_WITHIN(delta, expected, actual, num_elements)                     UNITY_TEST_ASSERT_UINT64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_size_t_ARRAY_WITHIN(delta, expected, actual, num_elements)                     UNITY_TEST_ASSERT_UINT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_HEX_ARRAY_WITHIN(delta, expected, actual, num_elements)                        UNITY_TEST_ASSERT_HEX32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_HEX8_ARRAY_WITHIN(delta, expected, actual, num_elements)                       UNITY_TEST_ASSERT_HEX8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_HEX16_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_HEX16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_HEX32_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_HEX32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_HEX64_ARRAY_WITHIN(delta, expected, actual, num_elements)                      UNITY_TEST_ASSERT_HEX64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)
#define TEST_ASSERT_CHAR_ARRAY_WITHIN(delta, expected, actual, num_elements)                       UNITY_TEST_ASSERT_CHAR_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, NULL)


/* Structs and Strings */
#define TEST_ASSERT_EQUAL_PTR(expected, actual)                                                    UNITY_TEST_ASSERT_EQUAL_PTR((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_STRING(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_STRING((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_STRING_LEN(expected, actual, len)                                        UNITY_TEST_ASSERT_EQUAL_STRING_LEN((expected), (actual), (len), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_MEMORY(expected, actual, len)                                            UNITY_TEST_ASSERT_EQUAL_MEMORY((expected), (actual), (len), __LINE__, NULL)

/* Arrays */
#define TEST_ASSERT_EQUAL_INT_ARRAY(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EQUAL_INT_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT8_ARRAY(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EQUAL_INT8_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT16_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_INT16_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT32_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_INT32_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_INT64_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_INT64_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT_ARRAY(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EQUAL_UINT_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_UINT8_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT16_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_UINT16_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT32_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_UINT32_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_UINT64_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_UINT64_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_size_t_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_UINT_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX_ARRAY(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EQUAL_HEX32_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EQUAL_HEX8_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX16_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_HEX16_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX32_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_HEX32_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_HEX64_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_HEX64_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_PTR_ARRAY(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EQUAL_PTR_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_STRING_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_STRING_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_MEMORY_ARRAY(expected, actual, len, num_elements)                        UNITY_TEST_ASSERT_EQUAL_MEMORY_ARRAY((expected), (actual), (len), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_CHAR_ARRAY(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EQUAL_CHAR_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)

/* Arrays Compared To Single Value */
#define TEST_ASSERT_EACH_EQUAL_INT(expected, actual, num_elements)                                 UNITY_TEST_ASSERT_EACH_EQUAL_INT((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_INT8(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EACH_EQUAL_INT8((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_INT16(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_INT16((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_INT32(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_INT32((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_INT64(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_INT64((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_UINT(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EACH_EQUAL_UINT((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_UINT8(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_UINT8((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_UINT16(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_UINT16((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_UINT32(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_UINT32((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_UINT64(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_UINT64((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_size_t(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_UINT((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_HEX(expected, actual, num_elements)                                 UNITY_TEST_ASSERT_EACH_EQUAL_HEX32((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_HEX8(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EACH_EQUAL_HEX8((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_HEX16(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_HEX16((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_HEX32(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_HEX32((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_HEX64(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_HEX64((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_PTR(expected, actual, num_elements)                                 UNITY_TEST_ASSERT_EACH_EQUAL_PTR((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_STRING(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_STRING((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_MEMORY(expected, actual, len, num_elements)                         UNITY_TEST_ASSERT_EACH_EQUAL_MEMORY((expected), (actual), (len), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_CHAR(expected, actual, num_elements)                                UNITY_TEST_ASSERT_EACH_EQUAL_CHAR((expected), (actual), (num_elements), __LINE__, NULL)

/* Floating Point (If Enabled) */
#define TEST_ASSERT_FLOAT_WITHIN(delta, expected, actual)                                          UNITY_TEST_ASSERT_FLOAT_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_FLOAT(expected, actual)                                                  UNITY_TEST_ASSERT_EQUAL_FLOAT((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_FLOAT_ARRAY(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EQUAL_FLOAT_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_FLOAT(expected, actual, num_elements)                               UNITY_TEST_ASSERT_EACH_EQUAL_FLOAT((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_INF(actual)                                                           UNITY_TEST_ASSERT_FLOAT_IS_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NEG_INF(actual)                                                       UNITY_TEST_ASSERT_FLOAT_IS_NEG_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NAN(actual)                                                           UNITY_TEST_ASSERT_FLOAT_IS_NAN((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_DETERMINATE(actual)                                                   UNITY_TEST_ASSERT_FLOAT_IS_DETERMINATE((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NOT_INF(actual)                                                       UNITY_TEST_ASSERT_FLOAT_IS_NOT_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NOT_NEG_INF(actual)                                                   UNITY_TEST_ASSERT_FLOAT_IS_NOT_NEG_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NOT_NAN(actual)                                                       UNITY_TEST_ASSERT_FLOAT_IS_NOT_NAN((actual), __LINE__, NULL)
#define TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE(actual)                                               UNITY_TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE((actual), __LINE__, NULL)

/* Double (If Enabled) */
#define TEST_ASSERT_DOUBLE_WITHIN(delta, expected, actual)                                         UNITY_TEST_ASSERT_DOUBLE_WITHIN((delta), (expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_DOUBLE(expected, actual)                                                 UNITY_TEST_ASSERT_EQUAL_DOUBLE((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_EQUAL_DOUBLE_ARRAY(expected, actual, num_elements)                             UNITY_TEST_ASSERT_EQUAL_DOUBLE_ARRAY((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_EACH_EQUAL_DOUBLE(expected, actual, num_elements)                              UNITY_TEST_ASSERT_EACH_EQUAL_DOUBLE((expected), (actual), (num_elements), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_INF(actual)                                                          UNITY_TEST_ASSERT_DOUBLE_IS_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NEG_INF(actual)                                                      UNITY_TEST_ASSERT_DOUBLE_IS_NEG_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NAN(actual)                                                          UNITY_TEST_ASSERT_DOUBLE_IS_NAN((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_DETERMINATE(actual)                                                  UNITY_TEST_ASSERT_DOUBLE_IS_DETERMINATE((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NOT_INF(actual)                                                      UNITY_TEST_ASSERT_DOUBLE_IS_NOT_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF(actual)                                                  UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NOT_NAN(actual)                                                      UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NAN((actual), __LINE__, NULL)
#define TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE(actual)                                              UNITY_TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE((actual), __LINE__, NULL)

/* Shorthand */
#ifdef UNITY_SHORTHAND_AS_OLD
#define TEST_ASSERT_EQUAL(expected, actual)                                                        UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                                                    UNITY_TEST_ASSERT(((expected) != (actual)), __LINE__, " Expected Not-Equal")
#endif
#ifdef UNITY_SHORTHAND_AS_INT
#define TEST_ASSERT_EQUAL(expected, actual)                                                        UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                                                    UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif
#ifdef UNITY_SHORTHAND_AS_MEM
#define TEST_ASSERT_EQUAL(expected, actual)                                                        UNITY_TEST_ASSERT_EQUAL_MEMORY((&expected), (&actual), sizeof(expected), __LINE__, NULL)
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                                                    UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif
#ifdef UNITY_SHORTHAND_AS_RAW
#define TEST_ASSERT_EQUAL(expected, actual)                                                        UNITY_TEST_ASSERT(((expected) == (actual)), __LINE__, " Expected Equal")
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                                                    UNITY_TEST_ASSERT(((expected) != (actual)), __LINE__, " Expected Not-Equal")
#endif
#ifdef UNITY_SHORTHAND_AS_NONE
#define TEST_ASSERT_EQUAL(expected, actual)                                                        UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                                                    UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif

/*-------------------------------------------------------
 * Test Asserts (with additional messages)
 *-------------------------------------------------------*/

/* Boolean */
#define TEST_ASSERT_MESSAGE(condition, message)                                                    UNITY_TEST_ASSERT(       (condition), __LINE__, (message))
#define TEST_ASSERT_TRUE_MESSAGE(condition, message)                                               UNITY_TEST_ASSERT(       (condition), __LINE__, (message))
#define TEST_ASSERT_UNLESS_MESSAGE(condition, message)                                             UNITY_TEST_ASSERT(      !(condition), __LINE__, (message))
#define TEST_ASSERT_FALSE_MESSAGE(condition, message)                                              UNITY_TEST_ASSERT(      !(condition), __LINE__, (message))
#define TEST_ASSERT_NULL_MESSAGE(pointer, message)                                                 UNITY_TEST_ASSERT_NULL(    (pointer), __LINE__, (message))
#define TEST_ASSERT_NOT_NULL_MESSAGE(pointer, message)                                             UNITY_TEST_ASSERT_NOT_NULL((pointer), __LINE__, (message))
#define TEST_ASSERT_EMPTY_MESSAGE(pointer, message)                                                UNITY_TEST_ASSERT_EMPTY(    (pointer), __LINE__, (message))
#define TEST_ASSERT_NOT_EMPTY_MESSAGE(pointer, message)                                            UNITY_TEST_ASSERT_NOT_EMPTY((pointer), __LINE__, (message))

/* Integers (of all sizes) */
#define TEST_ASSERT_EQUAL_INT_MESSAGE(expected, actual, message)                                   UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT8_MESSAGE(expected, actual, message)                                  UNITY_TEST_ASSERT_EQUAL_INT8((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT16_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_INT16((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT32_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_INT32((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT64_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_INT64((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT_MESSAGE(expected, actual, message)                                  UNITY_TEST_ASSERT_EQUAL_UINT( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_UINT8( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT16_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_UINT16( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT32_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_UINT32( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT64_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_UINT64( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_size_t_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_UINT( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX_MESSAGE(expected, actual, message)                                   UNITY_TEST_ASSERT_EQUAL_HEX32((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX8_MESSAGE(expected, actual, message)                                  UNITY_TEST_ASSERT_EQUAL_HEX8( (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX16_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_HEX16((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX32_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_HEX32((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX64_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_HEX64((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_BITS_MESSAGE(mask, expected, actual, message)                                  UNITY_TEST_ASSERT_BITS((mask), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_BITS_HIGH_MESSAGE(mask, actual, message)                                       UNITY_TEST_ASSERT_BITS((mask), (UNITY_UINT32)(-1), (actual), __LINE__, (message))
#define TEST_ASSERT_BITS_LOW_MESSAGE(mask, actual, message)                                        UNITY_TEST_ASSERT_BITS((mask), (UNITY_UINT32)(0), (actual), __LINE__, (message))
#define TEST_ASSERT_BIT_HIGH_MESSAGE(bit, actual, message)                                         UNITY_TEST_ASSERT_BITS(((UNITY_UINT32)1 << (bit)), (UNITY_UINT32)(-1), (actual), __LINE__, (message))
#define TEST_ASSERT_BIT_LOW_MESSAGE(bit, actual, message)                                          UNITY_TEST_ASSERT_BITS(((UNITY_UINT32)1 << (bit)), (UNITY_UINT32)(0), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_CHAR_MESSAGE(expected, actual, message)                                  UNITY_TEST_ASSERT_EQUAL_CHAR((expected), (actual), __LINE__, (message))

/* Integer Not Equal To (of all sizes) */
#define TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(threshold, actual, message)                              UNITY_TEST_ASSERT_NOT_EQUAL_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_INT8_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_NOT_EQUAL_INT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_INT16_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_INT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_INT32_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_INT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_INT64_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_INT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_UINT_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_NOT_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_UINT8_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_UINT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_UINT16_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_NOT_EQUAL_UINT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_UINT32_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_NOT_EQUAL_UINT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_UINT64_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_NOT_EQUAL_UINT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_size_t_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_NOT_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_HEX8_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_NOT_EQUAL_HEX8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_HEX16_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_HEX16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_HEX32_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_HEX32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_HEX64_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_NOT_EQUAL_HEX64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_CHAR_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_NOT_EQUAL_CHAR((threshold), (actual), __LINE__, (message))


/* Integer Greater Than/ Less Than (of all sizes) */
#define TEST_ASSERT_GREATER_THAN_MESSAGE(threshold, actual, message)                               UNITY_TEST_ASSERT_GREATER_THAN_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_INT_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_GREATER_THAN_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_INT8_MESSAGE(threshold, actual, message)                          UNITY_TEST_ASSERT_GREATER_THAN_INT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_INT16_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_INT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_INT32_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_INT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_INT64_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_INT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_UINT_MESSAGE(threshold, actual, message)                          UNITY_TEST_ASSERT_GREATER_THAN_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_UINT8_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_UINT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_UINT16_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_GREATER_THAN_UINT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_UINT32_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_GREATER_THAN_UINT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_UINT64_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_GREATER_THAN_UINT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_size_t_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_GREATER_THAN_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_HEX8_MESSAGE(threshold, actual, message)                          UNITY_TEST_ASSERT_GREATER_THAN_HEX8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_HEX16_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_HEX16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_HEX32_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_HEX32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_HEX64_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_GREATER_THAN_HEX64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_THAN_CHAR_MESSAGE(threshold, actual, message)                          UNITY_TEST_ASSERT_GREATER_THAN_CHAR((threshold), (actual), __LINE__, (message))

#define TEST_ASSERT_LESS_THAN_MESSAGE(threshold, actual, message)                                  UNITY_TEST_ASSERT_SMALLER_THAN_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_INT_MESSAGE(threshold, actual, message)                              UNITY_TEST_ASSERT_SMALLER_THAN_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_INT8_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_SMALLER_THAN_INT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_INT16_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_INT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_INT32_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_INT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_INT64_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_INT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_UINT_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_SMALLER_THAN_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_UINT8_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_UINT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_UINT16_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_SMALLER_THAN_UINT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_UINT32_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_SMALLER_THAN_UINT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_UINT64_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_SMALLER_THAN_UINT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_size_t_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_SMALLER_THAN_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_HEX8_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_SMALLER_THAN_HEX8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_HEX16_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_HEX16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_HEX32_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_HEX32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_HEX64_MESSAGE(threshold, actual, message)                            UNITY_TEST_ASSERT_SMALLER_THAN_HEX64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_THAN_CHAR_MESSAGE(threshold, actual, message)                             UNITY_TEST_ASSERT_SMALLER_THAN_CHAR((threshold), (actual), __LINE__, (message))

#define TEST_ASSERT_GREATER_OR_EQUAL_MESSAGE(threshold, actual, message)                           UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(threshold, actual, message)                       UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_INT8_MESSAGE(threshold, actual, message)                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_INT16_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_INT32_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_INT64_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT_MESSAGE(threshold, actual, message)                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT8_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT16_MESSAGE(threshold, actual, message)                    UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT32_MESSAGE(threshold, actual, message)                    UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_UINT64_MESSAGE(threshold, actual, message)                    UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_size_t_MESSAGE(threshold, actual, message)                    UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX8_MESSAGE(threshold, actual, message)                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX16_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX32_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_HEX64_MESSAGE(threshold, actual, message)                     UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_GREATER_OR_EQUAL_CHAR_MESSAGE(threshold, actual, message)                      UNITY_TEST_ASSERT_GREATER_OR_EQUAL_CHAR((threshold), (actual), __LINE__, (message))

#define TEST_ASSERT_LESS_OR_EQUAL_MESSAGE(threshold, actual, message)                              UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_INT_MESSAGE(threshold, actual, message)                          UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_INT8_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_INT16_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_INT32_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_INT64_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_UINT_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_UINT8_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_UINT16_MESSAGE(threshold, actual, message)                       UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_UINT32_MESSAGE(threshold, actual, message)                       UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_UINT64_MESSAGE(threshold, actual, message)                       UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_size_t_MESSAGE(threshold, actual, message)                       UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_HEX8_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX8((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_HEX16_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX16((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_HEX32_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX32((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_HEX64_MESSAGE(threshold, actual, message)                        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX64((threshold), (actual), __LINE__, (message))
#define TEST_ASSERT_LESS_OR_EQUAL_CHAR_MESSAGE(threshold, actual, message)                         UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_CHAR((threshold), (actual), __LINE__, (message))

/* Integer Ranges (of all sizes) */
#define TEST_ASSERT_INT_WITHIN_MESSAGE(delta, expected, actual, message)                           UNITY_TEST_ASSERT_INT_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_INT8_WITHIN_MESSAGE(delta, expected, actual, message)                          UNITY_TEST_ASSERT_INT8_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_INT16_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_INT16_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_INT32_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_INT32_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_INT64_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_INT64_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_UINT_WITHIN_MESSAGE(delta, expected, actual, message)                          UNITY_TEST_ASSERT_UINT_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_UINT8_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_UINT8_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_UINT16_WITHIN_MESSAGE(delta, expected, actual, message)                        UNITY_TEST_ASSERT_UINT16_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_UINT32_WITHIN_MESSAGE(delta, expected, actual, message)                        UNITY_TEST_ASSERT_UINT32_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_UINT64_WITHIN_MESSAGE(delta, expected, actual, message)                        UNITY_TEST_ASSERT_UINT64_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_size_t_WITHIN_MESSAGE(delta, expected, actual, message)                        UNITY_TEST_ASSERT_UINT_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_HEX_WITHIN_MESSAGE(delta, expected, actual, message)                           UNITY_TEST_ASSERT_HEX32_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_HEX8_WITHIN_MESSAGE(delta, expected, actual, message)                          UNITY_TEST_ASSERT_HEX8_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_HEX16_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_HEX16_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_HEX32_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_HEX32_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_HEX64_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_HEX64_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_CHAR_WITHIN_MESSAGE(delta, expected, actual, message)                          UNITY_TEST_ASSERT_CHAR_WITHIN((delta), (expected), (actual), __LINE__, (message))

/* Integer Array Ranges (of all sizes) */
#define TEST_ASSERT_INT_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)       UNITY_TEST_ASSERT_INT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_INT8_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)      UNITY_TEST_ASSERT_INT8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_INT16_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_INT16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_INT32_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_INT32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_INT64_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_INT64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_UINT_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)      UNITY_TEST_ASSERT_UINT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_UINT8_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_UINT8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_UINT16_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)    UNITY_TEST_ASSERT_UINT16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_UINT32_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)    UNITY_TEST_ASSERT_UINT32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_UINT64_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)    UNITY_TEST_ASSERT_UINT64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_size_t_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)    UNITY_TEST_ASSERT_UINT_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_HEX_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)       UNITY_TEST_ASSERT_HEX32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_HEX8_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)      UNITY_TEST_ASSERT_HEX8_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_HEX16_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_HEX16_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_HEX32_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_HEX32_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_HEX64_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)     UNITY_TEST_ASSERT_HEX64_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))
#define TEST_ASSERT_CHAR_ARRAY_WITHIN_MESSAGE(delta, expected, actual, num_elements, message)      UNITY_TEST_ASSERT_CHAR_ARRAY_WITHIN((delta), (expected), (actual), num_elements, __LINE__, (message))


/* Structs and Strings */
#define TEST_ASSERT_EQUAL_PTR_MESSAGE(expected, actual, message)                                   UNITY_TEST_ASSERT_EQUAL_PTR((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_STRING((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(expected, actual, len, message)                       UNITY_TEST_ASSERT_EQUAL_STRING_LEN((expected), (actual), (len), __LINE__, (message))
#define TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, actual, len, message)                           UNITY_TEST_ASSERT_EQUAL_MEMORY((expected), (actual), (len), __LINE__, (message))

/* Arrays */
#define TEST_ASSERT_EQUAL_INT_ARRAY_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EQUAL_INT_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EQUAL_INT8_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT16_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_INT16_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT32_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_INT32_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_INT64_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_INT64_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT_ARRAY_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EQUAL_UINT_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_UINT8_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT16_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_UINT16_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT32_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_UINT32_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_UINT64_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_UINT64_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_size_t_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_UINT_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX_ARRAY_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EQUAL_HEX32_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EQUAL_HEX8_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX16_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_HEX16_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX32_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_HEX32_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_HEX64_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_HEX64_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_PTR_ARRAY_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EQUAL_PTR_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_STRING_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_STRING_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_MEMORY_ARRAY_MESSAGE(expected, actual, len, num_elements, message)       UNITY_TEST_ASSERT_EQUAL_MEMORY_ARRAY((expected), (actual), (len), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EQUAL_CHAR_ARRAY_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EQUAL_CHAR_ARRAY((expected), (actual), (num_elements), __LINE__, (message))

/* Arrays Compared To Single Value*/
#define TEST_ASSERT_EACH_EQUAL_INT_MESSAGE(expected, actual, num_elements, message)                UNITY_TEST_ASSERT_EACH_EQUAL_INT((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_INT8_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EACH_EQUAL_INT8((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_INT16_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_INT16((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_INT32_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_INT32((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_INT64_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_INT64((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_UINT_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EACH_EQUAL_UINT((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_UINT8_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_UINT8((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_UINT16_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_UINT16((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_UINT32_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_UINT32((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_UINT64_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_UINT64((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_size_t_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_UINT((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_HEX_MESSAGE(expected, actual, num_elements, message)                UNITY_TEST_ASSERT_EACH_EQUAL_HEX32((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_HEX8_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EACH_EQUAL_HEX8((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_HEX16_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_HEX16((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_HEX32_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_HEX32((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_HEX64_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_HEX64((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_PTR_MESSAGE(expected, actual, num_elements, message)                UNITY_TEST_ASSERT_EACH_EQUAL_PTR((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_STRING_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_STRING((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_MEMORY_MESSAGE(expected, actual, len, num_elements, message)        UNITY_TEST_ASSERT_EACH_EQUAL_MEMORY((expected), (actual), (len), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_CHAR_MESSAGE(expected, actual, num_elements, message)               UNITY_TEST_ASSERT_EACH_EQUAL_CHAR((expected), (actual), (num_elements), __LINE__, (message))

/* Floating Point (If Enabled) */
#define TEST_ASSERT_FLOAT_WITHIN_MESSAGE(delta, expected, actual, message)                         UNITY_TEST_ASSERT_FLOAT_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_FLOAT_MESSAGE(expected, actual, message)                                 UNITY_TEST_ASSERT_EQUAL_FLOAT((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_FLOAT_ARRAY_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EQUAL_FLOAT_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_FLOAT_MESSAGE(expected, actual, num_elements, message)              UNITY_TEST_ASSERT_EACH_EQUAL_FLOAT((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_INF_MESSAGE(actual, message)                                          UNITY_TEST_ASSERT_FLOAT_IS_INF((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NEG_INF_MESSAGE(actual, message)                                      UNITY_TEST_ASSERT_FLOAT_IS_NEG_INF((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NAN_MESSAGE(actual, message)                                          UNITY_TEST_ASSERT_FLOAT_IS_NAN((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_DETERMINATE_MESSAGE(actual, message)                                  UNITY_TEST_ASSERT_FLOAT_IS_DETERMINATE((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NOT_INF_MESSAGE(actual, message)                                      UNITY_TEST_ASSERT_FLOAT_IS_NOT_INF((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NOT_NEG_INF_MESSAGE(actual, message)                                  UNITY_TEST_ASSERT_FLOAT_IS_NOT_NEG_INF((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NOT_NAN_MESSAGE(actual, message)                                      UNITY_TEST_ASSERT_FLOAT_IS_NOT_NAN((actual), __LINE__, (message))
#define TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE_MESSAGE(actual, message)                              UNITY_TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE((actual), __LINE__, (message))

/* Double (If Enabled) */
#define TEST_ASSERT_DOUBLE_WITHIN_MESSAGE(delta, expected, actual, message)                        UNITY_TEST_ASSERT_DOUBLE_WITHIN((delta), (expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_DOUBLE_MESSAGE(expected, actual, message)                                UNITY_TEST_ASSERT_EQUAL_DOUBLE((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_EQUAL_DOUBLE_ARRAY_MESSAGE(expected, actual, num_elements, message)            UNITY_TEST_ASSERT_EQUAL_DOUBLE_ARRAY((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_EACH_EQUAL_DOUBLE_MESSAGE(expected, actual, num_elements, message)             UNITY_TEST_ASSERT_EACH_EQUAL_DOUBLE((expected), (actual), (num_elements), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_INF_MESSAGE(actual, message)                                         UNITY_TEST_ASSERT_DOUBLE_IS_INF((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NEG_INF_MESSAGE(actual, message)                                     UNITY_TEST_ASSERT_DOUBLE_IS_NEG_INF((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NAN_MESSAGE(actual, message)                                         UNITY_TEST_ASSERT_DOUBLE_IS_NAN((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_DETERMINATE_MESSAGE(actual, message)                                 UNITY_TEST_ASSERT_DOUBLE_IS_DETERMINATE((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NOT_INF_MESSAGE(actual, message)                                     UNITY_TEST_ASSERT_DOUBLE_IS_NOT_INF((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF_MESSAGE(actual, message)                                 UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NOT_NAN_MESSAGE(actual, message)                                     UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NAN((actual), __LINE__, (message))
#define TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE_MESSAGE(actual, message)                             UNITY_TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE((actual), __LINE__, (message))

/* Shorthand */
#ifdef UNITY_SHORTHAND_AS_OLD
#define TEST_ASSERT_EQUAL_MESSAGE(expected, actual, message)                                       UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, (message))
#define TEST_ASSERT_NOT_EQUAL_MESSAGE(expected, actual, message)                                   UNITY_TEST_ASSERT(((expected) != (actual)), __LINE__, (message))
#endif
#ifdef UNITY_SHORTHAND_AS_INT
#define TEST_ASSERT_EQUAL_MESSAGE(expected, actual, message)                                       UNITY_TEST_ASSERT_EQUAL_INT((expected), (actual), __LINE__, message)
#define TEST_ASSERT_NOT_EQUAL_MESSAGE(expected, actual, message)                                   UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif
#ifdef  UNITY_SHORTHAND_AS_MEM
#define TEST_ASSERT_EQUAL_MESSAGE(expected, actual, message)                                       UNITY_TEST_ASSERT_EQUAL_MEMORY((&expected), (&actual), sizeof(expected), __LINE__, message)
#define TEST_ASSERT_NOT_EQUAL_MESSAGE(expected, actual, message)                                   UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif
#ifdef  UNITY_SHORTHAND_AS_RAW
#define TEST_ASSERT_EQUAL_MESSAGE(expected, actual, message)                                       UNITY_TEST_ASSERT(((expected) == (actual)), __LINE__, message)
#define TEST_ASSERT_NOT_EQUAL_MESSAGE(expected, actual, message)                                   UNITY_TEST_ASSERT(((expected) != (actual)), __LINE__, message)
#endif
#ifdef UNITY_SHORTHAND_AS_NONE
#define TEST_ASSERT_EQUAL_MESSAGE(expected, actual, message)                                       UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#define TEST_ASSERT_NOT_EQUAL_MESSAGE(expected, actual, message)                                   UNITY_TEST_FAIL(__LINE__, UnityStrErrShorthand)
#endif

/* end of UNITY_FRAMEWORK_H */
#ifdef __cplusplus
}
#endif
#endif

