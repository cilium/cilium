/* ==========================================
    Unity Project - A Test Framework for C
    Copyright (c) 2007-21 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
========================================== */

#ifndef UNITY_INTERNALS_H
#define UNITY_INTERNALS_H

#ifdef UNITY_INCLUDE_CONFIG_H
#include "unity_config.h"
#endif

#ifndef UNITY_EXCLUDE_SETJMP_H
#include <setjmp.h>
#endif

#ifndef UNITY_EXCLUDE_MATH_H
#include <math.h>
#endif

#ifndef UNITY_EXCLUDE_STDDEF_H
#include <stddef.h>
#endif

#ifdef UNITY_INCLUDE_PRINT_FORMATTED
#include <stdarg.h>
#endif

/* Unity Attempts to Auto-Detect Integer Types
 * Attempt 1: UINT_MAX, ULONG_MAX in <limits.h>, or default to 32 bits
 * Attempt 2: UINTPTR_MAX in <stdint.h>, or default to same size as long
 * The user may override any of these derived constants:
 * UNITY_INT_WIDTH, UNITY_LONG_WIDTH, UNITY_POINTER_WIDTH */
#ifndef UNITY_EXCLUDE_STDINT_H
#include <stdint.h>
#endif

#ifndef UNITY_EXCLUDE_LIMITS_H
#include <limits.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define UNITY_FUNCTION_ATTR(a)    __attribute__((a))
#else
  #define UNITY_FUNCTION_ATTR(a)    /* ignore */
#endif

#ifndef UNITY_NORETURN
  #if defined(__cplusplus)
    #if __cplusplus >= 201103L
      #define UNITY_NORETURN [[ noreturn ]]
    #endif
  #elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #include <stdnoreturn.h>
    #define UNITY_NORETURN noreturn
  #endif
#endif
#ifndef UNITY_NORETURN
  #define UNITY_NORETURN UNITY_FUNCTION_ATTR(noreturn)
#endif

/*-------------------------------------------------------
 * Guess Widths If Not Specified
 *-------------------------------------------------------*/

/* Determine the size of an int, if not already specified.
 * We cannot use sizeof(int), because it is not yet defined
 * at this stage in the translation of the C program.
 * Also sizeof(int) does return the size in addressable units on all platforms,
 * which may not necessarily be the size in bytes.
 * Therefore, infer it from UINT_MAX if possible. */
#ifndef UNITY_INT_WIDTH
  #ifdef UINT_MAX
    #if (UINT_MAX == 0xFFFF)
      #define UNITY_INT_WIDTH (16)
    #elif (UINT_MAX == 0xFFFFFFFF)
      #define UNITY_INT_WIDTH (32)
    #elif (UINT_MAX == 0xFFFFFFFFFFFFFFFF)
      #define UNITY_INT_WIDTH (64)
    #endif
  #else /* Set to default */
    #define UNITY_INT_WIDTH (32)
  #endif /* UINT_MAX */
#endif

/* Determine the size of a long, if not already specified. */
#ifndef UNITY_LONG_WIDTH
  #ifdef ULONG_MAX
    #if (ULONG_MAX == 0xFFFF)
      #define UNITY_LONG_WIDTH (16)
    #elif (ULONG_MAX == 0xFFFFFFFF)
      #define UNITY_LONG_WIDTH (32)
    #elif (ULONG_MAX == 0xFFFFFFFFFFFFFFFF)
      #define UNITY_LONG_WIDTH (64)
    #endif
  #else /* Set to default */
    #define UNITY_LONG_WIDTH (32)
  #endif /* ULONG_MAX */
#endif

/* Determine the size of a pointer, if not already specified. */
#ifndef UNITY_POINTER_WIDTH
  #ifdef UINTPTR_MAX
    #if (UINTPTR_MAX <= 0xFFFF)
      #define UNITY_POINTER_WIDTH (16)
    #elif (UINTPTR_MAX <= 0xFFFFFFFF)
      #define UNITY_POINTER_WIDTH (32)
    #elif (UINTPTR_MAX <= 0xFFFFFFFFFFFFFFFF)
      #define UNITY_POINTER_WIDTH (64)
    #endif
  #else /* Set to default */
    #define UNITY_POINTER_WIDTH UNITY_LONG_WIDTH
  #endif /* UINTPTR_MAX */
#endif

/*-------------------------------------------------------
 * Int Support (Define types based on detected sizes)
 *-------------------------------------------------------*/

#if (UNITY_INT_WIDTH == 32)
    typedef unsigned char   UNITY_UINT8;
    typedef unsigned short  UNITY_UINT16;
    typedef unsigned int    UNITY_UINT32;
    typedef signed char     UNITY_INT8;
    typedef signed short    UNITY_INT16;
    typedef signed int      UNITY_INT32;
#elif (UNITY_INT_WIDTH == 16)
    typedef unsigned char   UNITY_UINT8;
    typedef unsigned int    UNITY_UINT16;
    typedef unsigned long   UNITY_UINT32;
    typedef signed char     UNITY_INT8;
    typedef signed int      UNITY_INT16;
    typedef signed long     UNITY_INT32;
#else
    #error Invalid UNITY_INT_WIDTH specified! (16 or 32 are supported)
#endif

/*-------------------------------------------------------
 * 64-bit Support
 *-------------------------------------------------------*/

/* Auto-detect 64 Bit Support */
#ifndef UNITY_SUPPORT_64
  #if UNITY_LONG_WIDTH == 64 || UNITY_POINTER_WIDTH == 64
    #define UNITY_SUPPORT_64
  #endif
#endif

/* 64-Bit Support Dependent Configuration */
#ifndef UNITY_SUPPORT_64
    /* No 64-bit Support */
    typedef UNITY_UINT32 UNITY_UINT;
    typedef UNITY_INT32  UNITY_INT;
    #define UNITY_MAX_NIBBLES (8)  /* Maximum number of nibbles in a UNITY_(U)INT */
#else
  /* 64-bit Support */
  #if (UNITY_LONG_WIDTH == 32)
    typedef unsigned long long UNITY_UINT64;
    typedef signed long long   UNITY_INT64;
  #elif (UNITY_LONG_WIDTH == 64)
    typedef unsigned long      UNITY_UINT64;
    typedef signed long        UNITY_INT64;
  #else
    #error Invalid UNITY_LONG_WIDTH specified! (32 or 64 are supported)
  #endif
    typedef UNITY_UINT64 UNITY_UINT;
    typedef UNITY_INT64  UNITY_INT;
    #define UNITY_MAX_NIBBLES (16) /* Maximum number of nibbles in a UNITY_(U)INT */
#endif

/*-------------------------------------------------------
 * Pointer Support
 *-------------------------------------------------------*/

#if (UNITY_POINTER_WIDTH == 32)
  #define UNITY_PTR_TO_INT UNITY_INT32
  #define UNITY_DISPLAY_STYLE_POINTER UNITY_DISPLAY_STYLE_HEX32
#elif (UNITY_POINTER_WIDTH == 64)
  #define UNITY_PTR_TO_INT UNITY_INT64
  #define UNITY_DISPLAY_STYLE_POINTER UNITY_DISPLAY_STYLE_HEX64
#elif (UNITY_POINTER_WIDTH == 16)
  #define UNITY_PTR_TO_INT UNITY_INT16
  #define UNITY_DISPLAY_STYLE_POINTER UNITY_DISPLAY_STYLE_HEX16
#else
  #error Invalid UNITY_POINTER_WIDTH specified! (16, 32 or 64 are supported)
#endif

#ifndef UNITY_PTR_ATTRIBUTE
  #define UNITY_PTR_ATTRIBUTE
#endif

#ifndef UNITY_INTERNAL_PTR
  #define UNITY_INTERNAL_PTR UNITY_PTR_ATTRIBUTE const void*
#endif

/*-------------------------------------------------------
 * Float Support
 *-------------------------------------------------------*/

#ifdef UNITY_EXCLUDE_FLOAT

/* No Floating Point Support */
#ifndef UNITY_EXCLUDE_DOUBLE
#define UNITY_EXCLUDE_DOUBLE /* Remove double when excluding float support */
#endif
#ifndef UNITY_EXCLUDE_FLOAT_PRINT
#define UNITY_EXCLUDE_FLOAT_PRINT
#endif

#else

/* Floating Point Support */
#ifndef UNITY_FLOAT_PRECISION
#define UNITY_FLOAT_PRECISION (0.00001f)
#endif
#ifndef UNITY_FLOAT_TYPE
#define UNITY_FLOAT_TYPE float
#endif
typedef UNITY_FLOAT_TYPE UNITY_FLOAT;

/* isinf & isnan macros should be provided by math.h */
#ifndef isinf
/* The value of Inf - Inf is NaN */
#define isinf(n) (isnan((n) - (n)) && !isnan(n))
#endif

#ifndef isnan
/* NaN is the only floating point value that does NOT equal itself.
 * Therefore if n != n, then it is NaN. */
#define isnan(n) ((n != n) ? 1 : 0)
#endif

#endif

/*-------------------------------------------------------
 * Double Float Support
 *-------------------------------------------------------*/

/* unlike float, we DON'T include by default */
#if defined(UNITY_EXCLUDE_DOUBLE) || !defined(UNITY_INCLUDE_DOUBLE)

  /* No Floating Point Support */
  #ifndef UNITY_EXCLUDE_DOUBLE
  #define UNITY_EXCLUDE_DOUBLE
  #else
    #undef UNITY_INCLUDE_DOUBLE
  #endif

  #ifndef UNITY_EXCLUDE_FLOAT
    #ifndef UNITY_DOUBLE_TYPE
    #define UNITY_DOUBLE_TYPE double
    #endif
  typedef UNITY_FLOAT UNITY_DOUBLE;
  /* For parameter in UnityPrintFloat(UNITY_DOUBLE), which aliases to double or float */
  #endif

#else

  /* Double Floating Point Support */
  #ifndef UNITY_DOUBLE_PRECISION
  #define UNITY_DOUBLE_PRECISION (1e-12)
  #endif

  #ifndef UNITY_DOUBLE_TYPE
  #define UNITY_DOUBLE_TYPE double
  #endif
  typedef UNITY_DOUBLE_TYPE UNITY_DOUBLE;

#endif

/*-------------------------------------------------------
 * Output Method: stdout (DEFAULT)
 *-------------------------------------------------------*/
#ifndef UNITY_OUTPUT_CHAR
  /* Default to using putchar, which is defined in stdio.h */
  #include <stdio.h>
  #define UNITY_OUTPUT_CHAR(a) (void)putchar(a)
#else
  /* If defined as something else, make sure we declare it here so it's ready for use */
  #ifdef UNITY_OUTPUT_CHAR_HEADER_DECLARATION
    extern void UNITY_OUTPUT_CHAR_HEADER_DECLARATION;
  #endif
#endif

#ifndef UNITY_OUTPUT_FLUSH
  #ifdef UNITY_USE_FLUSH_STDOUT
    /* We want to use the stdout flush utility */
    #include <stdio.h>
    #define UNITY_OUTPUT_FLUSH() (void)fflush(stdout)
  #else
    /* We've specified nothing, therefore flush should just be ignored */
    #define UNITY_OUTPUT_FLUSH()
  #endif
#else
  /* If defined as something else, make sure we declare it here so it's ready for use */
  #ifdef UNITY_OUTPUT_FLUSH_HEADER_DECLARATION
    extern void UNITY_OUTPUT_FLUSH_HEADER_DECLARATION;
  #endif
#endif

#ifndef UNITY_OUTPUT_FLUSH
#define UNITY_FLUSH_CALL()
#else
#define UNITY_FLUSH_CALL() UNITY_OUTPUT_FLUSH()
#endif

#ifndef UNITY_PRINT_EOL
#define UNITY_PRINT_EOL()    UNITY_OUTPUT_CHAR('\n')
#endif

#ifndef UNITY_OUTPUT_START
#define UNITY_OUTPUT_START()
#endif

#ifndef UNITY_OUTPUT_COMPLETE
#define UNITY_OUTPUT_COMPLETE()
#endif

#ifdef UNITY_INCLUDE_EXEC_TIME
  #if !defined(UNITY_EXEC_TIME_START) && \
      !defined(UNITY_EXEC_TIME_STOP) && \
      !defined(UNITY_PRINT_EXEC_TIME) && \
      !defined(UNITY_TIME_TYPE)
      /* If none any of these macros are defined then try to provide a default implementation */

    #if defined(UNITY_CLOCK_MS)
      /* This is a simple way to get a default implementation on platforms that support getting a millisecond counter */
      #define UNITY_TIME_TYPE UNITY_UINT
      #define UNITY_EXEC_TIME_START() Unity.CurrentTestStartTime = UNITY_CLOCK_MS()
      #define UNITY_EXEC_TIME_STOP() Unity.CurrentTestStopTime = UNITY_CLOCK_MS()
      #define UNITY_PRINT_EXEC_TIME() { \
        UNITY_UINT execTimeMs = (Unity.CurrentTestStopTime - Unity.CurrentTestStartTime); \
        UnityPrint(" ("); \
        UnityPrintNumberUnsigned(execTimeMs); \
        UnityPrint(" ms)"); \
        }
    #elif defined(_WIN32)
      #include <time.h>
      #define UNITY_TIME_TYPE clock_t
      #define UNITY_GET_TIME(t) t = (clock_t)((clock() * 1000) / CLOCKS_PER_SEC)
      #define UNITY_EXEC_TIME_START() UNITY_GET_TIME(Unity.CurrentTestStartTime)
      #define UNITY_EXEC_TIME_STOP() UNITY_GET_TIME(Unity.CurrentTestStopTime)
      #define UNITY_PRINT_EXEC_TIME() { \
        UNITY_UINT execTimeMs = (Unity.CurrentTestStopTime - Unity.CurrentTestStartTime); \
        UnityPrint(" ("); \
        UnityPrintNumberUnsigned(execTimeMs); \
        UnityPrint(" ms)"); \
        }
    #elif defined(__unix__) || defined(__APPLE__)
      #include <time.h>
      #define UNITY_TIME_TYPE struct timespec
      #define UNITY_GET_TIME(t) clock_gettime(CLOCK_MONOTONIC, &t)
      #define UNITY_EXEC_TIME_START() UNITY_GET_TIME(Unity.CurrentTestStartTime)
      #define UNITY_EXEC_TIME_STOP() UNITY_GET_TIME(Unity.CurrentTestStopTime)
      #define UNITY_PRINT_EXEC_TIME() { \
        UNITY_UINT execTimeMs = ((Unity.CurrentTestStopTime.tv_sec - Unity.CurrentTestStartTime.tv_sec) * 1000L); \
        execTimeMs += ((Unity.CurrentTestStopTime.tv_nsec - Unity.CurrentTestStartTime.tv_nsec) / 1000000L); \
        UnityPrint(" ("); \
        UnityPrintNumberUnsigned(execTimeMs); \
        UnityPrint(" ms)"); \
        }
    #endif
  #endif
#endif

#ifndef UNITY_EXEC_TIME_START
#define UNITY_EXEC_TIME_START() do{}while(0)
#endif

#ifndef UNITY_EXEC_TIME_STOP
#define UNITY_EXEC_TIME_STOP() do{}while(0)
#endif

#ifndef UNITY_TIME_TYPE
#define UNITY_TIME_TYPE UNITY_UINT
#endif

#ifndef UNITY_PRINT_EXEC_TIME
#define UNITY_PRINT_EXEC_TIME() do{}while(0)
#endif

/*-------------------------------------------------------
 * Footprint
 *-------------------------------------------------------*/

#ifndef UNITY_LINE_TYPE
#define UNITY_LINE_TYPE UNITY_UINT
#endif

#ifndef UNITY_COUNTER_TYPE
#define UNITY_COUNTER_TYPE UNITY_UINT
#endif

/*-------------------------------------------------------
 * Internal Structs Needed
 *-------------------------------------------------------*/

typedef void (*UnityTestFunction)(void);

#define UNITY_DISPLAY_RANGE_INT  (0x10)
#define UNITY_DISPLAY_RANGE_UINT (0x20)
#define UNITY_DISPLAY_RANGE_HEX  (0x40)
#define UNITY_DISPLAY_RANGE_CHAR (0x80)

typedef enum
{
    UNITY_DISPLAY_STYLE_INT      = (UNITY_INT_WIDTH / 8) + UNITY_DISPLAY_RANGE_INT,
    UNITY_DISPLAY_STYLE_INT8     = 1 + UNITY_DISPLAY_RANGE_INT,
    UNITY_DISPLAY_STYLE_INT16    = 2 + UNITY_DISPLAY_RANGE_INT,
    UNITY_DISPLAY_STYLE_INT32    = 4 + UNITY_DISPLAY_RANGE_INT,
#ifdef UNITY_SUPPORT_64
    UNITY_DISPLAY_STYLE_INT64    = 8 + UNITY_DISPLAY_RANGE_INT,
#endif

    UNITY_DISPLAY_STYLE_UINT     = (UNITY_INT_WIDTH / 8) + UNITY_DISPLAY_RANGE_UINT,
    UNITY_DISPLAY_STYLE_UINT8    = 1 + UNITY_DISPLAY_RANGE_UINT,
    UNITY_DISPLAY_STYLE_UINT16   = 2 + UNITY_DISPLAY_RANGE_UINT,
    UNITY_DISPLAY_STYLE_UINT32   = 4 + UNITY_DISPLAY_RANGE_UINT,
#ifdef UNITY_SUPPORT_64
    UNITY_DISPLAY_STYLE_UINT64   = 8 + UNITY_DISPLAY_RANGE_UINT,
#endif

    UNITY_DISPLAY_STYLE_HEX8     = 1 + UNITY_DISPLAY_RANGE_HEX,
    UNITY_DISPLAY_STYLE_HEX16    = 2 + UNITY_DISPLAY_RANGE_HEX,
    UNITY_DISPLAY_STYLE_HEX32    = 4 + UNITY_DISPLAY_RANGE_HEX,
#ifdef UNITY_SUPPORT_64
    UNITY_DISPLAY_STYLE_HEX64    = 8 + UNITY_DISPLAY_RANGE_HEX,
#endif

    UNITY_DISPLAY_STYLE_CHAR     = 1 + UNITY_DISPLAY_RANGE_CHAR + UNITY_DISPLAY_RANGE_INT,

    UNITY_DISPLAY_STYLE_UNKNOWN
} UNITY_DISPLAY_STYLE_T;

typedef enum
{
    UNITY_WITHIN           = 0x0,
    UNITY_EQUAL_TO         = 0x1,
    UNITY_GREATER_THAN     = 0x2,
    UNITY_GREATER_OR_EQUAL = 0x2 + UNITY_EQUAL_TO,
    UNITY_SMALLER_THAN     = 0x4,
    UNITY_SMALLER_OR_EQUAL = 0x4 + UNITY_EQUAL_TO,
    UNITY_NOT_EQUAL        = 0x0,
    UNITY_UNKNOWN
} UNITY_COMPARISON_T;

#ifndef UNITY_EXCLUDE_FLOAT
typedef enum UNITY_FLOAT_TRAIT
{
    UNITY_FLOAT_IS_NOT_INF       = 0,
    UNITY_FLOAT_IS_INF,
    UNITY_FLOAT_IS_NOT_NEG_INF,
    UNITY_FLOAT_IS_NEG_INF,
    UNITY_FLOAT_IS_NOT_NAN,
    UNITY_FLOAT_IS_NAN,
    UNITY_FLOAT_IS_NOT_DET,
    UNITY_FLOAT_IS_DET,
    UNITY_FLOAT_INVALID_TRAIT
} UNITY_FLOAT_TRAIT_T;
#endif

typedef enum
{
    UNITY_ARRAY_TO_VAL = 0,
    UNITY_ARRAY_TO_ARRAY,
    UNITY_ARRAY_UNKNOWN
} UNITY_FLAGS_T;

struct UNITY_STORAGE_T
{
    const char* TestFile;
    const char* CurrentTestName;
#ifndef UNITY_EXCLUDE_DETAILS
    const char* CurrentDetail1;
    const char* CurrentDetail2;
#endif
    UNITY_LINE_TYPE CurrentTestLineNumber;
    UNITY_COUNTER_TYPE NumberOfTests;
    UNITY_COUNTER_TYPE TestFailures;
    UNITY_COUNTER_TYPE TestIgnores;
    UNITY_COUNTER_TYPE CurrentTestFailed;
    UNITY_COUNTER_TYPE CurrentTestIgnored;
#ifdef UNITY_INCLUDE_EXEC_TIME
    UNITY_TIME_TYPE CurrentTestStartTime;
    UNITY_TIME_TYPE CurrentTestStopTime;
#endif
#ifndef UNITY_EXCLUDE_SETJMP_H
    jmp_buf AbortFrame;
#endif
};

extern struct UNITY_STORAGE_T Unity;

/*-------------------------------------------------------
 * Test Suite Management
 *-------------------------------------------------------*/

void UnityBegin(const char* filename);
int  UnityEnd(void);
void UnitySetTestFile(const char* filename);
void UnityConcludeTest(void);

#ifndef RUN_TEST
void UnityDefaultTestRun(UnityTestFunction Func, const char* FuncName, const int FuncLineNum);
#else
#define UNITY_SKIP_DEFAULT_RUNNER
#endif

/*-------------------------------------------------------
 * Details Support
 *-------------------------------------------------------*/

#ifdef UNITY_EXCLUDE_DETAILS
#define UNITY_CLR_DETAILS()
#define UNITY_SET_DETAIL(d1)
#define UNITY_SET_DETAILS(d1,d2)
#else
#define UNITY_CLR_DETAILS()      { Unity.CurrentDetail1 = 0;   Unity.CurrentDetail2 = 0;  }
#define UNITY_SET_DETAIL(d1)     { Unity.CurrentDetail1 = (d1);  Unity.CurrentDetail2 = 0;  }
#define UNITY_SET_DETAILS(d1,d2) { Unity.CurrentDetail1 = (d1);  Unity.CurrentDetail2 = (d2); }

#ifndef UNITY_DETAIL1_NAME
#define UNITY_DETAIL1_NAME "Function"
#endif

#ifndef UNITY_DETAIL2_NAME
#define UNITY_DETAIL2_NAME "Argument"
#endif
#endif

#ifdef UNITY_PRINT_TEST_CONTEXT
void UNITY_PRINT_TEST_CONTEXT(void);
#endif

/*-------------------------------------------------------
 * Test Output
 *-------------------------------------------------------*/

void UnityPrint(const char* string);

#ifdef UNITY_INCLUDE_PRINT_FORMATTED
void UnityPrintF(const UNITY_LINE_TYPE line, const char* format, ...);
#endif

void UnityPrintLen(const char* string, const UNITY_UINT32 length);
void UnityPrintMask(const UNITY_UINT mask, const UNITY_UINT number);
void UnityPrintNumberByStyle(const UNITY_INT number, const UNITY_DISPLAY_STYLE_T style);
void UnityPrintNumber(const UNITY_INT number_to_print);
void UnityPrintNumberUnsigned(const UNITY_UINT number);
void UnityPrintNumberHex(const UNITY_UINT number, const char nibbles_to_print);

#ifndef UNITY_EXCLUDE_FLOAT_PRINT
void UnityPrintFloat(const UNITY_DOUBLE input_number);
#endif

/*-------------------------------------------------------
 * Test Assertion Functions
 *-------------------------------------------------------
 *  Use the macros below this section instead of calling
 *  these directly. The macros have a consistent naming
 *  convention and will pull in file and line information
 *  for you. */

void UnityAssertEqualNumber(const UNITY_INT expected,
                            const UNITY_INT actual,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber,
                            const UNITY_DISPLAY_STYLE_T style);

void UnityAssertGreaterOrLessOrEqualNumber(const UNITY_INT threshold,
                                           const UNITY_INT actual,
                                           const UNITY_COMPARISON_T compare,
                                           const char *msg,
                                           const UNITY_LINE_TYPE lineNumber,
                                           const UNITY_DISPLAY_STYLE_T style);

void UnityAssertEqualIntArray(UNITY_INTERNAL_PTR expected,
                              UNITY_INTERNAL_PTR actual,
                              const UNITY_UINT32 num_elements,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_DISPLAY_STYLE_T style,
                              const UNITY_FLAGS_T flags);

void UnityAssertBits(const UNITY_INT mask,
                     const UNITY_INT expected,
                     const UNITY_INT actual,
                     const char* msg,
                     const UNITY_LINE_TYPE lineNumber);

void UnityAssertEqualString(const char* expected,
                            const char* actual,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber);

void UnityAssertEqualStringLen(const char* expected,
                            const char* actual,
                            const UNITY_UINT32 length,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber);

void UnityAssertEqualStringArray( UNITY_INTERNAL_PTR expected,
                                  const char** actual,
                                  const UNITY_UINT32 num_elements,
                                  const char* msg,
                                  const UNITY_LINE_TYPE lineNumber,
                                  const UNITY_FLAGS_T flags);

void UnityAssertEqualMemory( UNITY_INTERNAL_PTR expected,
                             UNITY_INTERNAL_PTR actual,
                             const UNITY_UINT32 length,
                             const UNITY_UINT32 num_elements,
                             const char* msg,
                             const UNITY_LINE_TYPE lineNumber,
                             const UNITY_FLAGS_T flags);

void UnityAssertNumbersWithin(const UNITY_UINT delta,
                              const UNITY_INT expected,
                              const UNITY_INT actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_DISPLAY_STYLE_T style);

void UnityAssertNumbersArrayWithin(const UNITY_UINT delta,
                                   UNITY_INTERNAL_PTR expected,
                                   UNITY_INTERNAL_PTR actual,
                                   const UNITY_UINT32 num_elements,
                                   const char* msg,
                                   const UNITY_LINE_TYPE lineNumber,
                                   const UNITY_DISPLAY_STYLE_T style,
                                   const UNITY_FLAGS_T flags);

#ifndef UNITY_EXCLUDE_SETJMP_H
UNITY_NORETURN void UnityFail(const char* message, const UNITY_LINE_TYPE line);
UNITY_NORETURN void UnityIgnore(const char* message, const UNITY_LINE_TYPE line);
#else
void UnityFail(const char* message, const UNITY_LINE_TYPE line);
void UnityIgnore(const char* message, const UNITY_LINE_TYPE line);
#endif

void UnityMessage(const char* message, const UNITY_LINE_TYPE line);

#ifndef UNITY_EXCLUDE_FLOAT
void UnityAssertFloatsWithin(const UNITY_FLOAT delta,
                             const UNITY_FLOAT expected,
                             const UNITY_FLOAT actual,
                             const char* msg,
                             const UNITY_LINE_TYPE lineNumber);

void UnityAssertEqualFloatArray(UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* expected,
                                UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* actual,
                                const UNITY_UINT32 num_elements,
                                const char* msg,
                                const UNITY_LINE_TYPE lineNumber,
                                const UNITY_FLAGS_T flags);

void UnityAssertFloatSpecial(const UNITY_FLOAT actual,
                             const char* msg,
                             const UNITY_LINE_TYPE lineNumber,
                             const UNITY_FLOAT_TRAIT_T style);
#endif

#ifndef UNITY_EXCLUDE_DOUBLE
void UnityAssertDoublesWithin(const UNITY_DOUBLE delta,
                              const UNITY_DOUBLE expected,
                              const UNITY_DOUBLE actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber);

void UnityAssertEqualDoubleArray(UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* expected,
                                 UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* actual,
                                 const UNITY_UINT32 num_elements,
                                 const char* msg,
                                 const UNITY_LINE_TYPE lineNumber,
                                 const UNITY_FLAGS_T flags);

void UnityAssertDoubleSpecial(const UNITY_DOUBLE actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_FLOAT_TRAIT_T style);
#endif

/*-------------------------------------------------------
 * Helpers
 *-------------------------------------------------------*/

UNITY_INTERNAL_PTR UnityNumToPtr(const UNITY_INT num, const UNITY_UINT8 size);
#ifndef UNITY_EXCLUDE_FLOAT
UNITY_INTERNAL_PTR UnityFloatToPtr(const float num);
#endif
#ifndef UNITY_EXCLUDE_DOUBLE
UNITY_INTERNAL_PTR UnityDoubleToPtr(const double num);
#endif

/*-------------------------------------------------------
 * Error Strings We Might Need
 *-------------------------------------------------------*/

extern const char UnityStrOk[];
extern const char UnityStrPass[];
extern const char UnityStrFail[];
extern const char UnityStrIgnore[];

extern const char UnityStrErrFloat[];
extern const char UnityStrErrDouble[];
extern const char UnityStrErr64[];
extern const char UnityStrErrShorthand[];

/*-------------------------------------------------------
 * Test Running Macros
 *-------------------------------------------------------*/

#ifndef UNITY_EXCLUDE_SETJMP_H
#define TEST_PROTECT() (setjmp(Unity.AbortFrame) == 0)
#define TEST_ABORT() longjmp(Unity.AbortFrame, 1)
#else
#define TEST_PROTECT() 1
#define TEST_ABORT() return
#endif

/* This tricky series of macros gives us an optional line argument to treat it as RUN_TEST(func, num=__LINE__) */
#ifndef RUN_TEST
#ifdef __STDC_VERSION__
#if __STDC_VERSION__ >= 199901L
#define UNITY_SUPPORT_VARIADIC_MACROS
#endif
#endif
#ifdef UNITY_SUPPORT_VARIADIC_MACROS
#define RUN_TEST(...) RUN_TEST_AT_LINE(__VA_ARGS__, __LINE__, throwaway)
#define RUN_TEST_AT_LINE(func, line, ...) UnityDefaultTestRun(func, #func, line)
#endif
#endif

/* If we can't do the tricky version, we'll just have to require them to always include the line number */
#ifndef RUN_TEST
#ifdef CMOCK
#define RUN_TEST(func, num) UnityDefaultTestRun(func, #func, num)
#else
#define RUN_TEST(func) UnityDefaultTestRun(func, #func, __LINE__)
#endif
#endif

#define TEST_LINE_NUM (Unity.CurrentTestLineNumber)
#define TEST_IS_IGNORED (Unity.CurrentTestIgnored)
#define UNITY_NEW_TEST(a) \
    Unity.CurrentTestName = (a); \
    Unity.CurrentTestLineNumber = (UNITY_LINE_TYPE)(__LINE__); \
    Unity.NumberOfTests++;

#ifndef UNITY_BEGIN
#define UNITY_BEGIN() UnityBegin(__FILE__)
#endif

#ifndef UNITY_END
#define UNITY_END() UnityEnd()
#endif

#ifndef UNITY_SHORTHAND_AS_INT
#ifndef UNITY_SHORTHAND_AS_MEM
#ifndef UNITY_SHORTHAND_AS_NONE
#ifndef UNITY_SHORTHAND_AS_RAW
#define UNITY_SHORTHAND_AS_OLD
#endif
#endif
#endif
#endif

/*-----------------------------------------------
 * Command Line Argument Support
 *-----------------------------------------------*/

#ifdef UNITY_USE_COMMAND_LINE_ARGS
int UnityParseOptions(int argc, char** argv);
int UnityTestMatches(void);
#endif

/*-------------------------------------------------------
 * Basic Fail and Ignore
 *-------------------------------------------------------*/

#define UNITY_TEST_FAIL(line, message)   UnityFail(   (message), (UNITY_LINE_TYPE)(line))
#define UNITY_TEST_IGNORE(line, message) UnityIgnore( (message), (UNITY_LINE_TYPE)(line))

/*-------------------------------------------------------
 * Test Asserts
 *-------------------------------------------------------*/

#define UNITY_TEST_ASSERT(condition, line, message)                                              do {if (condition) {} else {UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), (message));}} while(0)
#define UNITY_TEST_ASSERT_NULL(pointer, line, message)                                           UNITY_TEST_ASSERT(((pointer) == NULL),  (UNITY_LINE_TYPE)(line), (message))
#define UNITY_TEST_ASSERT_NOT_NULL(pointer, line, message)                                       UNITY_TEST_ASSERT(((pointer) != NULL),  (UNITY_LINE_TYPE)(line), (message))
#define UNITY_TEST_ASSERT_EMPTY(pointer, line, message)                                          UNITY_TEST_ASSERT(((pointer[0]) == 0),  (UNITY_LINE_TYPE)(line), (message))
#define UNITY_TEST_ASSERT_NOT_EMPTY(pointer, line, message)                                      UNITY_TEST_ASSERT(((pointer[0]) != 0),  (UNITY_LINE_TYPE)(line), (message))

#define UNITY_TEST_ASSERT_EQUAL_INT(expected, actual, line, message)                             UnityAssertEqualNumber((UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_EQUAL_INT8(expected, actual, line, message)                            UnityAssertEqualNumber((UNITY_INT)(UNITY_INT8 )(expected), (UNITY_INT)(UNITY_INT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_EQUAL_INT16(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(UNITY_INT16)(expected), (UNITY_INT)(UNITY_INT16)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_EQUAL_INT32(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(UNITY_INT32)(expected), (UNITY_INT)(UNITY_INT32)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_EQUAL_UINT(expected, actual, line, message)                            UnityAssertEqualNumber((UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_EQUAL_UINT8(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT8 )(expected), (UNITY_INT)(UNITY_UINT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_EQUAL_UINT16(expected, actual, line, message)                          UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT16)(expected), (UNITY_INT)(UNITY_UINT16)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_EQUAL_UINT32(expected, actual, line, message)                          UnityAssertEqualNumber((UNITY_INT)(UNITY_UINT32)(expected), (UNITY_INT)(UNITY_UINT32)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_EQUAL_HEX8(expected, actual, line, message)                            UnityAssertEqualNumber((UNITY_INT)(UNITY_INT8 )(expected), (UNITY_INT)(UNITY_INT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_EQUAL_HEX16(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(UNITY_INT16)(expected), (UNITY_INT)(UNITY_INT16)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_EQUAL_HEX32(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(UNITY_INT32)(expected), (UNITY_INT)(UNITY_INT32)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_EQUAL_CHAR(expected, actual, line, message)                            UnityAssertEqualNumber((UNITY_INT)(UNITY_INT8 )(expected), (UNITY_INT)(UNITY_INT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)
#define UNITY_TEST_ASSERT_BITS(mask, expected, actual, line, message)                            UnityAssertBits((UNITY_INT)(mask), (UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line))

#define UNITY_TEST_ASSERT_NOT_EQUAL_INT(threshold, actual, line, message)                        UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),               (UNITY_INT)(actual),               UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_NOT_EQUAL_INT8(threshold, actual, line, message)                       UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold),  (UNITY_INT)(UNITY_INT8 )(actual),  UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_NOT_EQUAL_INT16(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT16)(threshold),  (UNITY_INT)(UNITY_INT16)(actual),  UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_NOT_EQUAL_INT32(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT32)(threshold),  (UNITY_INT)(UNITY_INT32)(actual),  UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_NOT_EQUAL_UINT(threshold, actual, line, message)                       UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),               (UNITY_INT)(actual),               UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_NOT_EQUAL_UINT8(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_NOT_EQUAL_UINT16(threshold, actual, line, message)                     UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_NOT_EQUAL_UINT32(threshold, actual, line, message)                     UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_NOT_EQUAL_HEX8(threshold, actual, line, message)                       UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_NOT_EQUAL_HEX16(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_NOT_EQUAL_HEX32(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_NOT_EQUAL_CHAR(threshold, actual, line, message)                       UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold),  (UNITY_INT)(UNITY_INT8 )(actual),  UNITY_NOT_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_GREATER_THAN_INT(threshold, actual, line, message)                     UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),              (UNITY_INT)(actual),              UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_GREATER_THAN_INT8(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold), (UNITY_INT)(UNITY_INT8 )(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_GREATER_THAN_INT16(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT16)(threshold), (UNITY_INT)(UNITY_INT16)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_GREATER_THAN_INT32(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT32)(threshold), (UNITY_INT)(UNITY_INT32)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),              (UNITY_INT)(actual),              UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT8(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT16(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT32(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_GREATER_THAN_HEX8(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_GREATER_THAN_HEX16(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_GREATER_THAN_HEX32(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_GREATER_THAN_CHAR(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold), (UNITY_INT)(UNITY_INT8 )(actual), UNITY_GREATER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_SMALLER_THAN_INT(threshold, actual, line, message)                     UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),              (UNITY_INT)(actual),              UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_SMALLER_THAN_INT8(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold), (UNITY_INT)(UNITY_INT8 )(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_SMALLER_THAN_INT16(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT16)(threshold), (UNITY_INT)(UNITY_INT16)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_SMALLER_THAN_INT32(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT32)(threshold), (UNITY_INT)(UNITY_INT32)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold),              (UNITY_INT)(actual),              UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT8(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT16(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT32(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_SMALLER_THAN_HEX8(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_SMALLER_THAN_HEX16(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_SMALLER_THAN_HEX32(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_SMALLER_THAN_CHAR(threshold, actual, line, message)                    UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold), (UNITY_INT)(UNITY_INT8 )(actual), UNITY_SMALLER_THAN, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT(threshold, actual, line, message)                 UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)              (threshold), (UNITY_INT)              (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT8(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 ) (threshold), (UNITY_INT)(UNITY_INT8 ) (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT16(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT16) (threshold), (UNITY_INT)(UNITY_INT16) (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT32(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT32) (threshold), (UNITY_INT)(UNITY_INT32) (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)              (threshold), (UNITY_INT)              (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT8(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT16(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT32(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX8(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX16(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX32(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_CHAR(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 ) (threshold), (UNITY_INT)(UNITY_INT8 ) (actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT(threshold, actual, line, message)                 UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)             (threshold),  (UNITY_INT)              (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT8(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold),  (UNITY_INT)(UNITY_INT8 ) (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT16(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT16)(threshold),  (UNITY_INT)(UNITY_INT16) (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT32(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT32)(threshold),  (UNITY_INT)(UNITY_INT32) (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)             (threshold),  (UNITY_INT)              (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT8(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT16(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT32(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX8(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT8 )(threshold), (UNITY_INT)(UNITY_UINT8 )(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX16(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT16)(threshold), (UNITY_INT)(UNITY_UINT16)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX32(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_UINT32)(threshold), (UNITY_INT)(UNITY_UINT32)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_CHAR(threshold, actual, line, message)                UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(UNITY_INT8 )(threshold),  (UNITY_INT)(UNITY_INT8 ) (actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_INT_WITHIN(delta, expected, actual, line, message)                     UnityAssertNumbersWithin(              (delta), (UNITY_INT)                          (expected), (UNITY_INT)                          (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT)
#define UNITY_TEST_ASSERT_INT8_WITHIN(delta, expected, actual, line, message)                    UnityAssertNumbersWithin((UNITY_UINT8 )(delta), (UNITY_INT)(UNITY_INT8 )             (expected), (UNITY_INT)(UNITY_INT8 )             (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8)
#define UNITY_TEST_ASSERT_INT16_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((UNITY_UINT16)(delta), (UNITY_INT)(UNITY_INT16)             (expected), (UNITY_INT)(UNITY_INT16)             (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16)
#define UNITY_TEST_ASSERT_INT32_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((UNITY_UINT32)(delta), (UNITY_INT)(UNITY_INT32)             (expected), (UNITY_INT)(UNITY_INT32)             (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32)
#define UNITY_TEST_ASSERT_UINT_WITHIN(delta, expected, actual, line, message)                    UnityAssertNumbersWithin(              (delta), (UNITY_INT)                          (expected), (UNITY_INT)                          (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT)
#define UNITY_TEST_ASSERT_UINT8_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((UNITY_UINT8 )(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT8 )(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8)
#define UNITY_TEST_ASSERT_UINT16_WITHIN(delta, expected, actual, line, message)                  UnityAssertNumbersWithin((UNITY_UINT16)(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT16)(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT16)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16)
#define UNITY_TEST_ASSERT_UINT32_WITHIN(delta, expected, actual, line, message)                  UnityAssertNumbersWithin((UNITY_UINT32)(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT32)(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT32)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32)
#define UNITY_TEST_ASSERT_HEX8_WITHIN(delta, expected, actual, line, message)                    UnityAssertNumbersWithin((UNITY_UINT8 )(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT8 )(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT8 )(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8)
#define UNITY_TEST_ASSERT_HEX16_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((UNITY_UINT16)(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT16)(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT16)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16)
#define UNITY_TEST_ASSERT_HEX32_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((UNITY_UINT32)(delta), (UNITY_INT)(UNITY_UINT)(UNITY_UINT32)(expected), (UNITY_INT)(UNITY_UINT)(UNITY_UINT32)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32)
#define UNITY_TEST_ASSERT_CHAR_WITHIN(delta, expected, actual, line, message)                    UnityAssertNumbersWithin((UNITY_UINT8 )(delta), (UNITY_INT)(UNITY_INT8 )             (expected), (UNITY_INT)(UNITY_INT8 )             (actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR)

#define UNITY_TEST_ASSERT_INT_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)     UnityAssertNumbersArrayWithin(              (delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_INT8_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)    UnityAssertNumbersArrayWithin((UNITY_UINT8 )(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_INT16_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT16)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_INT32_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT32)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_UINT_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)    UnityAssertNumbersArrayWithin(              (delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_UINT8_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT16)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_UINT16_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)  UnityAssertNumbersArrayWithin((UNITY_UINT16)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_UINT32_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)  UnityAssertNumbersArrayWithin((UNITY_UINT32)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_HEX8_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)    UnityAssertNumbersArrayWithin((UNITY_UINT8 )(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_HEX16_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT16)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_HEX32_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT32)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_CHAR_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)    UnityAssertNumbersArrayWithin((UNITY_UINT8 )(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), ((UNITY_UINT32)(num_elements)), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR, UNITY_ARRAY_TO_ARRAY)


#define UNITY_TEST_ASSERT_EQUAL_PTR(expected, actual, line, message)                             UnityAssertEqualNumber((UNITY_PTR_TO_INT)(expected), (UNITY_PTR_TO_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_POINTER)
#define UNITY_TEST_ASSERT_EQUAL_STRING(expected, actual, line, message)                          UnityAssertEqualString((const char*)(expected), (const char*)(actual), (message), (UNITY_LINE_TYPE)(line))
#define UNITY_TEST_ASSERT_EQUAL_STRING_LEN(expected, actual, len, line, message)                 UnityAssertEqualStringLen((const char*)(expected), (const char*)(actual), (UNITY_UINT32)(len), (message), (UNITY_LINE_TYPE)(line))
#define UNITY_TEST_ASSERT_EQUAL_MEMORY(expected, actual, len, line, message)                     UnityAssertEqualMemory((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(len), 1, (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_ARRAY)

#define UNITY_TEST_ASSERT_EQUAL_INT_ARRAY(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT,     UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_INT8_ARRAY(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8,    UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_INT16_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16,   UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_INT32_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32,   UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_UINT_ARRAY(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT,    UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8,   UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_UINT16_ARRAY(expected, actual, num_elements, line, message)      UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16,  UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_UINT32_ARRAY(expected, actual, num_elements, line, message)      UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32,  UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8,    UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_HEX16_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16,   UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_HEX32_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32,   UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_PTR_ARRAY(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_POINTER, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_STRING_ARRAY(expected, actual, num_elements, line, message)      UnityAssertEqualStringArray((UNITY_INTERNAL_PTR)(expected), (const char**)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_MEMORY_ARRAY(expected, actual, len, num_elements, line, message) UnityAssertEqualMemory((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(len), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_CHAR_ARRAY(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR,    UNITY_ARRAY_TO_ARRAY)

#define UNITY_TEST_ASSERT_EACH_EQUAL_INT(expected, actual, num_elements, line, message)          UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)              (expected), (UNITY_INT_WIDTH / 8)),          (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT,     UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_INT8(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT8  )(expected), 1),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT8,    UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_INT16(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT16 )(expected), 2),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT16,   UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_INT32(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT32 )(expected), 4),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT32,   UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_UINT(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)              (expected), (UNITY_INT_WIDTH / 8)),          (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT,    UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_UINT8(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_UINT8 )(expected), 1),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT8,   UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_UINT16(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_UINT16)(expected), 2),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT16,  UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_UINT32(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_UINT32)(expected), 4),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT32,  UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_HEX8(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT8  )(expected), 1),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX8,    UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_HEX16(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT16 )(expected), 2),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX16,   UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_HEX32(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT32 )(expected), 4),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX32,   UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_PTR(expected, actual, num_elements, line, message)          UnityAssertEqualIntArray(UnityNumToPtr((UNITY_PTR_TO_INT)       (expected), (UNITY_POINTER_WIDTH / 8)),      (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_POINTER, UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_STRING(expected, actual, num_elements, line, message)       UnityAssertEqualStringArray((UNITY_INTERNAL_PTR)(expected), (const char**)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_MEMORY(expected, actual, len, num_elements, line, message)  UnityAssertEqualMemory((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(len), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_CHAR(expected, actual, num_elements, line, message)         UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT8  )(expected), 1),                              (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_CHAR,    UNITY_ARRAY_TO_VAL)

#ifdef UNITY_SUPPORT_64
#define UNITY_TEST_ASSERT_EQUAL_INT64(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_EQUAL_UINT64(expected, actual, line, message)                          UnityAssertEqualNumber((UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_EQUAL_HEX64(expected, actual, line, message)                           UnityAssertEqualNumber((UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_EQUAL_INT64_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64,  UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_UINT64_ARRAY(expected, actual, num_elements, line, message)      UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EQUAL_HEX64_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray((UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64,  UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EACH_EQUAL_INT64(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT64)(expected), 8), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64,  UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_UINT64(expected, actual, num_elements, line, message)       UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_UINT64)(expected), 8), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64, UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_EACH_EQUAL_HEX64(expected, actual, num_elements, line, message)        UnityAssertEqualIntArray(UnityNumToPtr((UNITY_INT)(UNITY_INT64)(expected), 8), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64,  UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_INT64_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((delta), (UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_UINT64_WITHIN(delta, expected, actual, line, message)                  UnityAssertNumbersWithin((delta), (UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_HEX64_WITHIN(delta, expected, actual, line, message)                   UnityAssertNumbersWithin((delta), (UNITY_INT)(expected), (UNITY_INT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_NOT_EQUAL_INT64(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_NOT_EQUAL,        (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_NOT_EQUAL_UINT64(threshold, actual, line, message)                     UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_NOT_EQUAL,        (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_NOT_EQUAL_HEX64(threshold, actual, line, message)                      UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_NOT_EQUAL,        (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_GREATER_THAN_INT64(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT64(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_GREATER_THAN_HEX64(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT64(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT64(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX64(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_GREATER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_INT64(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT64(threshold, actual, line, message)                  UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_HEX64(threshold, actual, line, message)                   UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_THAN,     (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT64(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT64(threshold, actual, line, message)              UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX64(threshold, actual, line, message)               UnityAssertGreaterOrLessOrEqualNumber((UNITY_INT)(threshold), (UNITY_INT)(actual), UNITY_SMALLER_OR_EQUAL, (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64)
#define UNITY_TEST_ASSERT_INT64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT64)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_INT64, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_UINT64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)  UnityAssertNumbersArrayWithin((UNITY_UINT64)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_UINT64, UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_HEX64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UnityAssertNumbersArrayWithin((UNITY_UINT64)(delta), (UNITY_INTERNAL_PTR)(expected), (UNITY_INTERNAL_PTR)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_DISPLAY_STYLE_HEX64, UNITY_ARRAY_TO_ARRAY)
#else
#define UNITY_TEST_ASSERT_EQUAL_INT64(expected, actual, line, message)                           UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_EQUAL_UINT64(expected, actual, line, message)                          UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_EQUAL_HEX64(expected, actual, line, message)                           UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_EQUAL_INT64_ARRAY(expected, actual, num_elements, line, message)       UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_EQUAL_UINT64_ARRAY(expected, actual, num_elements, line, message)      UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_EQUAL_HEX64_ARRAY(expected, actual, num_elements, line, message)       UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_INT64_WITHIN(delta, expected, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_UINT64_WITHIN(delta, expected, actual, line, message)                  UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_HEX64_WITHIN(delta, expected, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_THAN_INT64(threshold, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_THAN_UINT64(threshold, actual, line, message)                  UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_THAN_HEX64(threshold, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_INT64(threshold, actual, line, message)               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_UINT64(threshold, actual, line, message)              UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_GREATER_OR_EQUAL_HEX64(threshold, actual, line, message)               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_INT64(threshold, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_UINT64(threshold, actual, line, message)                  UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_THAN_HEX64(threshold, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT64(threshold, actual, line, message)               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_UINT64(threshold, actual, line, message)              UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_HEX64(threshold, actual, line, message)               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_INT64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_UINT64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)  UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#define UNITY_TEST_ASSERT_HEX64_ARRAY_WITHIN(delta, expected, actual, num_elements, line, message)   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErr64)
#endif

#ifdef UNITY_EXCLUDE_FLOAT
#define UNITY_TEST_ASSERT_FLOAT_WITHIN(delta, expected, actual, line, message)                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_EQUAL_FLOAT(expected, actual, line, message)                           UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_EQUAL_FLOAT_ARRAY(expected, actual, num_elements, line, message)       UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_EACH_EQUAL_FLOAT(expected, actual, num_elements, line, message)        UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_INF(actual, line, message)                                    UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NEG_INF(actual, line, message)                                UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NAN(actual, line, message)                                    UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_DETERMINATE(actual, line, message)                            UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_INF(actual, line, message)                                UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_NEG_INF(actual, line, message)                            UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_NAN(actual, line, message)                                UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE(actual, line, message)                        UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrFloat)
#else
#define UNITY_TEST_ASSERT_FLOAT_WITHIN(delta, expected, actual, line, message)                   UnityAssertFloatsWithin((UNITY_FLOAT)(delta), (UNITY_FLOAT)(expected), (UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line))
#define UNITY_TEST_ASSERT_EQUAL_FLOAT(expected, actual, line, message)                           UNITY_TEST_ASSERT_FLOAT_WITHIN((UNITY_FLOAT)(expected) * (UNITY_FLOAT)UNITY_FLOAT_PRECISION, (UNITY_FLOAT)(expected), (UNITY_FLOAT)(actual), (UNITY_LINE_TYPE)(line), (message))
#define UNITY_TEST_ASSERT_EQUAL_FLOAT_ARRAY(expected, actual, num_elements, line, message)       UnityAssertEqualFloatArray((UNITY_FLOAT*)(expected), (UNITY_FLOAT*)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EACH_EQUAL_FLOAT(expected, actual, num_elements, line, message)        UnityAssertEqualFloatArray(UnityFloatToPtr(expected), (UNITY_FLOAT*)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_FLOAT_IS_INF(actual, line, message)                                    UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_INF)
#define UNITY_TEST_ASSERT_FLOAT_IS_NEG_INF(actual, line, message)                                UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NEG_INF)
#define UNITY_TEST_ASSERT_FLOAT_IS_NAN(actual, line, message)                                    UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NAN)
#define UNITY_TEST_ASSERT_FLOAT_IS_DETERMINATE(actual, line, message)                            UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_DET)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_INF(actual, line, message)                                UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_INF)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_NEG_INF(actual, line, message)                            UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_NEG_INF)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_NAN(actual, line, message)                                UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_NAN)
#define UNITY_TEST_ASSERT_FLOAT_IS_NOT_DETERMINATE(actual, line, message)                        UnityAssertFloatSpecial((UNITY_FLOAT)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_DET)
#endif

#ifdef UNITY_EXCLUDE_DOUBLE
#define UNITY_TEST_ASSERT_DOUBLE_WITHIN(delta, expected, actual, line, message)                  UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_EQUAL_DOUBLE(expected, actual, line, message)                          UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_EQUAL_DOUBLE_ARRAY(expected, actual, num_elements, line, message)      UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_EACH_EQUAL_DOUBLE(expected, actual, num_elements, line, message)       UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_INF(actual, line, message)                                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NEG_INF(actual, line, message)                               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NAN(actual, line, message)                                   UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_DETERMINATE(actual, line, message)                           UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_INF(actual, line, message)                               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF(actual, line, message)                           UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NAN(actual, line, message)                               UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE(actual, line, message)                       UNITY_TEST_FAIL((UNITY_LINE_TYPE)(line), UnityStrErrDouble)
#else
#define UNITY_TEST_ASSERT_DOUBLE_WITHIN(delta, expected, actual, line, message)                  UnityAssertDoublesWithin((UNITY_DOUBLE)(delta), (UNITY_DOUBLE)(expected), (UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line))
#define UNITY_TEST_ASSERT_EQUAL_DOUBLE(expected, actual, line, message)                          UNITY_TEST_ASSERT_DOUBLE_WITHIN((UNITY_DOUBLE)(expected) * (UNITY_DOUBLE)UNITY_DOUBLE_PRECISION, (UNITY_DOUBLE)(expected), (UNITY_DOUBLE)(actual), (UNITY_LINE_TYPE)(line), (message))
#define UNITY_TEST_ASSERT_EQUAL_DOUBLE_ARRAY(expected, actual, num_elements, line, message)      UnityAssertEqualDoubleArray((UNITY_DOUBLE*)(expected), (UNITY_DOUBLE*)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_ARRAY)
#define UNITY_TEST_ASSERT_EACH_EQUAL_DOUBLE(expected, actual, num_elements, line, message)       UnityAssertEqualDoubleArray(UnityDoubleToPtr(expected), (UNITY_DOUBLE*)(actual), (UNITY_UINT32)(num_elements), (message), (UNITY_LINE_TYPE)(line), UNITY_ARRAY_TO_VAL)
#define UNITY_TEST_ASSERT_DOUBLE_IS_INF(actual, line, message)                                   UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_INF)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NEG_INF(actual, line, message)                               UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NEG_INF)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NAN(actual, line, message)                                   UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NAN)
#define UNITY_TEST_ASSERT_DOUBLE_IS_DETERMINATE(actual, line, message)                           UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_DET)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_INF(actual, line, message)                               UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_INF)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NEG_INF(actual, line, message)                           UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_NEG_INF)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_NAN(actual, line, message)                               UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_NAN)
#define UNITY_TEST_ASSERT_DOUBLE_IS_NOT_DETERMINATE(actual, line, message)                       UnityAssertDoubleSpecial((UNITY_DOUBLE)(actual), (message), (UNITY_LINE_TYPE)(line), UNITY_FLOAT_IS_NOT_DET)
#endif

/* End of UNITY_INTERNALS_H */
#endif

