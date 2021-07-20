/* =========================================================================
    Unity Project - A Test Framework for C
    Copyright (c) 2007-21 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
============================================================================ */

#include "unity.h"
#include <stddef.h>

#ifdef AVR
#include <avr/pgmspace.h>
#else
#define PROGMEM
#endif

/* If omitted from header, declare overrideable prototypes here so they're ready for use */
#ifdef UNITY_OMIT_OUTPUT_CHAR_HEADER_DECLARATION
void UNITY_OUTPUT_CHAR(int);
#endif

/* Helpful macros for us to use here in Assert functions */
#define UNITY_FAIL_AND_BAIL   { Unity.CurrentTestFailed  = 1; UNITY_OUTPUT_FLUSH(); TEST_ABORT(); }
#define UNITY_IGNORE_AND_BAIL { Unity.CurrentTestIgnored = 1; UNITY_OUTPUT_FLUSH(); TEST_ABORT(); }
#define RETURN_IF_FAIL_OR_IGNORE if (Unity.CurrentTestFailed || Unity.CurrentTestIgnored) TEST_ABORT()

struct UNITY_STORAGE_T Unity;

#ifdef UNITY_OUTPUT_COLOR
const char PROGMEM UnityStrOk[]                            = "\033[42mOK\033[00m";
const char PROGMEM UnityStrPass[]                          = "\033[42mPASS\033[00m";
const char PROGMEM UnityStrFail[]                          = "\033[41mFAIL\033[00m";
const char PROGMEM UnityStrIgnore[]                        = "\033[43mIGNORE\033[00m";
#else
const char PROGMEM UnityStrOk[]                            = "OK";
const char PROGMEM UnityStrPass[]                          = "PASS";
const char PROGMEM UnityStrFail[]                          = "FAIL";
const char PROGMEM UnityStrIgnore[]                        = "IGNORE";
#endif
static const char PROGMEM UnityStrNull[]                   = "NULL";
static const char PROGMEM UnityStrSpacer[]                 = ". ";
static const char PROGMEM UnityStrExpected[]               = " Expected ";
static const char PROGMEM UnityStrWas[]                    = " Was ";
static const char PROGMEM UnityStrGt[]                     = " to be greater than ";
static const char PROGMEM UnityStrLt[]                     = " to be less than ";
static const char PROGMEM UnityStrOrEqual[]                = "or equal to ";
static const char PROGMEM UnityStrNotEqual[]               = " to be not equal to ";
static const char PROGMEM UnityStrElement[]                = " Element ";
static const char PROGMEM UnityStrByte[]                   = " Byte ";
static const char PROGMEM UnityStrMemory[]                 = " Memory Mismatch.";
static const char PROGMEM UnityStrDelta[]                  = " Values Not Within Delta ";
static const char PROGMEM UnityStrPointless[]              = " You Asked Me To Compare Nothing, Which Was Pointless.";
static const char PROGMEM UnityStrNullPointerForExpected[] = " Expected pointer to be NULL";
static const char PROGMEM UnityStrNullPointerForActual[]   = " Actual pointer was NULL";
#ifndef UNITY_EXCLUDE_FLOAT
static const char PROGMEM UnityStrNot[]                    = "Not ";
static const char PROGMEM UnityStrInf[]                    = "Infinity";
static const char PROGMEM UnityStrNegInf[]                 = "Negative Infinity";
static const char PROGMEM UnityStrNaN[]                    = "NaN";
static const char PROGMEM UnityStrDet[]                    = "Determinate";
static const char PROGMEM UnityStrInvalidFloatTrait[]      = "Invalid Float Trait";
#endif
const char PROGMEM UnityStrErrShorthand[]                  = "Unity Shorthand Support Disabled";
const char PROGMEM UnityStrErrFloat[]                      = "Unity Floating Point Disabled";
const char PROGMEM UnityStrErrDouble[]                     = "Unity Double Precision Disabled";
const char PROGMEM UnityStrErr64[]                         = "Unity 64-bit Support Disabled";
static const char PROGMEM UnityStrBreaker[]                = "-----------------------";
static const char PROGMEM UnityStrResultsTests[]           = " Tests ";
static const char PROGMEM UnityStrResultsFailures[]        = " Failures ";
static const char PROGMEM UnityStrResultsIgnored[]         = " Ignored ";
#ifndef UNITY_EXCLUDE_DETAILS
static const char PROGMEM UnityStrDetail1Name[]            = UNITY_DETAIL1_NAME " ";
static const char PROGMEM UnityStrDetail2Name[]            = " " UNITY_DETAIL2_NAME " ";
#endif
/*-----------------------------------------------
 * Pretty Printers & Test Result Output Handlers
 *-----------------------------------------------*/

/*-----------------------------------------------*/
/* Local helper function to print characters. */
static void UnityPrintChar(const char* pch)
{
    /* printable characters plus CR & LF are printed */
    if ((*pch <= 126) && (*pch >= 32))
    {
        UNITY_OUTPUT_CHAR(*pch);
    }
    /* write escaped carriage returns */
    else if (*pch == 13)
    {
        UNITY_OUTPUT_CHAR('\\');
        UNITY_OUTPUT_CHAR('r');
    }
    /* write escaped line feeds */
    else if (*pch == 10)
    {
        UNITY_OUTPUT_CHAR('\\');
        UNITY_OUTPUT_CHAR('n');
    }
    /* unprintable characters are shown as codes */
    else
    {
        UNITY_OUTPUT_CHAR('\\');
        UNITY_OUTPUT_CHAR('x');
        UnityPrintNumberHex((UNITY_UINT)*pch, 2);
    }
}

/*-----------------------------------------------*/
/* Local helper function to print ANSI escape strings e.g. "\033[42m". */
#ifdef UNITY_OUTPUT_COLOR
static UNITY_UINT UnityPrintAnsiEscapeString(const char* string)
{
    const char* pch = string;
    UNITY_UINT count = 0;

    while (*pch && (*pch != 'm'))
    {
        UNITY_OUTPUT_CHAR(*pch);
        pch++;
        count++;
    }
    UNITY_OUTPUT_CHAR('m');
    count++;

    return count;
}
#endif

/*-----------------------------------------------*/
void UnityPrint(const char* string)
{
    const char* pch = string;

    if (pch != NULL)
    {
        while (*pch)
        {
#ifdef UNITY_OUTPUT_COLOR
            /* print ANSI escape code */
            if ((*pch == 27) && (*(pch + 1) == '['))
            {
                pch += UnityPrintAnsiEscapeString(pch);
                continue;
            }
#endif
            UnityPrintChar(pch);
            pch++;
        }
    }
}
/*-----------------------------------------------*/
void UnityPrintLen(const char* string, const UNITY_UINT32 length)
{
    const char* pch = string;

    if (pch != NULL)
    {
        while (*pch && ((UNITY_UINT32)(pch - string) < length))
        {
            /* printable characters plus CR & LF are printed */
            if ((*pch <= 126) && (*pch >= 32))
            {
                UNITY_OUTPUT_CHAR(*pch);
            }
            /* write escaped carriage returns */
            else if (*pch == 13)
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('r');
            }
            /* write escaped line feeds */
            else if (*pch == 10)
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('n');
            }
            /* unprintable characters are shown as codes */
            else
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('x');
                UnityPrintNumberHex((UNITY_UINT)*pch, 2);
            }
            pch++;
        }
    }
}

/*-----------------------------------------------*/
void UnityPrintNumberByStyle(const UNITY_INT number, const UNITY_DISPLAY_STYLE_T style)
{
    if ((style & UNITY_DISPLAY_RANGE_INT) == UNITY_DISPLAY_RANGE_INT)
    {
        if (style == UNITY_DISPLAY_STYLE_CHAR)
        {
            /* printable characters plus CR & LF are printed */
            UNITY_OUTPUT_CHAR('\'');
            if ((number <= 126) && (number >= 32))
            {
                UNITY_OUTPUT_CHAR((int)number);
            }
            /* write escaped carriage returns */
            else if (number == 13)
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('r');
            }
            /* write escaped line feeds */
            else if (number == 10)
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('n');
            }
            /* unprintable characters are shown as codes */
            else
            {
                UNITY_OUTPUT_CHAR('\\');
                UNITY_OUTPUT_CHAR('x');
                UnityPrintNumberHex((UNITY_UINT)number, 2);
            }
            UNITY_OUTPUT_CHAR('\'');
        }
        else
        {
            UnityPrintNumber(number);
        }
    }
    else if ((style & UNITY_DISPLAY_RANGE_UINT) == UNITY_DISPLAY_RANGE_UINT)
    {
        UnityPrintNumberUnsigned((UNITY_UINT)number);
    }
    else
    {
        UNITY_OUTPUT_CHAR('0');
        UNITY_OUTPUT_CHAR('x');
        UnityPrintNumberHex((UNITY_UINT)number, (char)((style & 0xF) * 2));
    }
}

/*-----------------------------------------------*/
void UnityPrintNumber(const UNITY_INT number_to_print)
{
    UNITY_UINT number = (UNITY_UINT)number_to_print;

    if (number_to_print < 0)
    {
        /* A negative number, including MIN negative */
        UNITY_OUTPUT_CHAR('-');
        number = (~number) + 1;
    }
    UnityPrintNumberUnsigned(number);
}

/*-----------------------------------------------
 * basically do an itoa using as little ram as possible */
void UnityPrintNumberUnsigned(const UNITY_UINT number)
{
    UNITY_UINT divisor = 1;

    /* figure out initial divisor */
    while (number / divisor > 9)
    {
        divisor *= 10;
    }

    /* now mod and print, then divide divisor */
    do
    {
        UNITY_OUTPUT_CHAR((char)('0' + (number / divisor % 10)));
        divisor /= 10;
    } while (divisor > 0);
}

/*-----------------------------------------------*/
void UnityPrintNumberHex(const UNITY_UINT number, const char nibbles_to_print)
{
    int nibble;
    char nibbles = nibbles_to_print;

    if ((unsigned)nibbles > UNITY_MAX_NIBBLES)
    {
        nibbles = UNITY_MAX_NIBBLES;
    }

    while (nibbles > 0)
    {
        nibbles--;
        nibble = (int)(number >> (nibbles * 4)) & 0x0F;
        if (nibble <= 9)
        {
            UNITY_OUTPUT_CHAR((char)('0' + nibble));
        }
        else
        {
            UNITY_OUTPUT_CHAR((char)('A' - 10 + nibble));
        }
    }
}

/*-----------------------------------------------*/
void UnityPrintMask(const UNITY_UINT mask, const UNITY_UINT number)
{
    UNITY_UINT current_bit = (UNITY_UINT)1 << (UNITY_INT_WIDTH - 1);
    UNITY_INT32 i;

    for (i = 0; i < UNITY_INT_WIDTH; i++)
    {
        if (current_bit & mask)
        {
            if (current_bit & number)
            {
                UNITY_OUTPUT_CHAR('1');
            }
            else
            {
                UNITY_OUTPUT_CHAR('0');
            }
        }
        else
        {
            UNITY_OUTPUT_CHAR('X');
        }
        current_bit = current_bit >> 1;
    }
}

/*-----------------------------------------------*/
#ifndef UNITY_EXCLUDE_FLOAT_PRINT
/*
 * This function prints a floating-point value in a format similar to
 * printf("%.7g") on a single-precision machine or printf("%.9g") on a
 * double-precision machine.  The 7th digit won't always be totally correct
 * in single-precision operation (for that level of accuracy, a more
 * complicated algorithm would be needed).
 */
void UnityPrintFloat(const UNITY_DOUBLE input_number)
{
#ifdef UNITY_INCLUDE_DOUBLE
    static const int sig_digits = 9;
    static const UNITY_INT32 min_scaled = 100000000;
    static const UNITY_INT32 max_scaled = 1000000000;
#else
    static const int sig_digits = 7;
    static const UNITY_INT32 min_scaled = 1000000;
    static const UNITY_INT32 max_scaled = 10000000;
#endif

    UNITY_DOUBLE number = input_number;

    /* print minus sign (does not handle negative zero) */
    if (number < 0.0f)
    {
        UNITY_OUTPUT_CHAR('-');
        number = -number;
    }

    /* handle zero, NaN, and +/- infinity */
    if (number == 0.0f)
    {
        UnityPrint("0");
    }
    else if (isnan(number))
    {
        UnityPrint("nan");
    }
    else if (isinf(number))
    {
        UnityPrint("inf");
    }
    else
    {
        UNITY_INT32 n_int = 0, n;
        int exponent = 0;
        int decimals, digits;
        char buf[16] = {0};

        /*
         * Scale up or down by powers of 10.  To minimize rounding error,
         * start with a factor/divisor of 10^10, which is the largest
         * power of 10 that can be represented exactly.  Finally, compute
         * (exactly) the remaining power of 10 and perform one more
         * multiplication or division.
         */
        if (number < 1.0f)
        {
            UNITY_DOUBLE factor = 1.0f;

            while (number < (UNITY_DOUBLE)max_scaled / 1e10f)  { number *= 1e10f; exponent -= 10; }
            while (number * factor < (UNITY_DOUBLE)min_scaled) { factor *= 10.0f; exponent--; }

            number *= factor;
        }
        else if (number > (UNITY_DOUBLE)max_scaled)
        {
            UNITY_DOUBLE divisor = 1.0f;

            while (number > (UNITY_DOUBLE)min_scaled * 1e10f)   { number  /= 1e10f; exponent += 10; }
            while (number / divisor > (UNITY_DOUBLE)max_scaled) { divisor *= 10.0f; exponent++; }

            number /= divisor;
        }
        else
        {
            /*
             * In this range, we can split off the integer part before
             * doing any multiplications.  This reduces rounding error by
             * freeing up significant bits in the fractional part.
             */
            UNITY_DOUBLE factor = 1.0f;
            n_int = (UNITY_INT32)number;
            number -= (UNITY_DOUBLE)n_int;

            while (n_int < min_scaled) { n_int *= 10; factor *= 10.0f; exponent--; }

            number *= factor;
        }

        /* round to nearest integer */
        n = ((UNITY_INT32)(number + number) + 1) / 2;

#ifndef UNITY_ROUND_TIES_AWAY_FROM_ZERO
        /* round to even if exactly between two integers */
        if ((n & 1) && (((UNITY_DOUBLE)n - number) == 0.5f))
            n--;
#endif

        n += n_int;

        if (n >= max_scaled)
        {
            n = min_scaled;
            exponent++;
        }

        /* determine where to place decimal point */
        decimals = ((exponent <= 0) && (exponent >= -(sig_digits + 3))) ? (-exponent) : (sig_digits - 1);
        exponent += decimals;

        /* truncate trailing zeroes after decimal point */
        while ((decimals > 0) && ((n % 10) == 0))
        {
            n /= 10;
            decimals--;
        }

        /* build up buffer in reverse order */
        digits = 0;
        while ((n != 0) || (digits <= decimals))
        {
            buf[digits++] = (char)('0' + n % 10);
            n /= 10;
        }
        while (digits > 0)
        {
            if (digits == decimals) { UNITY_OUTPUT_CHAR('.'); }
            UNITY_OUTPUT_CHAR(buf[--digits]);
        }

        /* print exponent if needed */
        if (exponent != 0)
        {
            UNITY_OUTPUT_CHAR('e');

            if (exponent < 0)
            {
                UNITY_OUTPUT_CHAR('-');
                exponent = -exponent;
            }
            else
            {
                UNITY_OUTPUT_CHAR('+');
            }

            digits = 0;
            while ((exponent != 0) || (digits < 2))
            {
                buf[digits++] = (char)('0' + exponent % 10);
                exponent /= 10;
            }
            while (digits > 0)
            {
                UNITY_OUTPUT_CHAR(buf[--digits]);
            }
        }
    }
}
#endif /* ! UNITY_EXCLUDE_FLOAT_PRINT */

/*-----------------------------------------------*/
static void UnityTestResultsBegin(const char* file, const UNITY_LINE_TYPE line)
{
#ifdef UNITY_OUTPUT_FOR_ECLIPSE
    UNITY_OUTPUT_CHAR('(');
    UnityPrint(file);
    UNITY_OUTPUT_CHAR(':');
    UnityPrintNumber((UNITY_INT)line);
    UNITY_OUTPUT_CHAR(')');
    UNITY_OUTPUT_CHAR(' ');
    UnityPrint(Unity.CurrentTestName);
    UNITY_OUTPUT_CHAR(':');
#else
#ifdef UNITY_OUTPUT_FOR_IAR_WORKBENCH
    UnityPrint("<SRCREF line=");
    UnityPrintNumber((UNITY_INT)line);
    UnityPrint(" file=\"");
    UnityPrint(file);
    UNITY_OUTPUT_CHAR('"');
    UNITY_OUTPUT_CHAR('>');
    UnityPrint(Unity.CurrentTestName);
    UnityPrint("</SRCREF> ");
#else
#ifdef UNITY_OUTPUT_FOR_QT_CREATOR
    UnityPrint("file://");
    UnityPrint(file);
    UNITY_OUTPUT_CHAR(':');
    UnityPrintNumber((UNITY_INT)line);
    UNITY_OUTPUT_CHAR(' ');
    UnityPrint(Unity.CurrentTestName);
    UNITY_OUTPUT_CHAR(':');
#else
    UnityPrint(file);
    UNITY_OUTPUT_CHAR(':');
    UnityPrintNumber((UNITY_INT)line);
    UNITY_OUTPUT_CHAR(':');
    UnityPrint(Unity.CurrentTestName);
    UNITY_OUTPUT_CHAR(':');
#endif
#endif
#endif
}

/*-----------------------------------------------*/
static void UnityTestResultsFailBegin(const UNITY_LINE_TYPE line)
{
    UnityTestResultsBegin(Unity.TestFile, line);
    UnityPrint(UnityStrFail);
    UNITY_OUTPUT_CHAR(':');
}

/*-----------------------------------------------*/
void UnityConcludeTest(void)
{
    if (Unity.CurrentTestIgnored)
    {
        Unity.TestIgnores++;
    }
    else if (!Unity.CurrentTestFailed)
    {
        UnityTestResultsBegin(Unity.TestFile, Unity.CurrentTestLineNumber);
        UnityPrint(UnityStrPass);
    }
    else
    {
        Unity.TestFailures++;
    }

    Unity.CurrentTestFailed = 0;
    Unity.CurrentTestIgnored = 0;
    UNITY_PRINT_EXEC_TIME();
    UNITY_PRINT_EOL();
    UNITY_FLUSH_CALL();
}

/*-----------------------------------------------*/
static void UnityAddMsgIfSpecified(const char* msg)
{
    if (msg)
    {
        UnityPrint(UnityStrSpacer);

#ifdef UNITY_PRINT_TEST_CONTEXT
        UNITY_PRINT_TEST_CONTEXT();
#endif
#ifndef UNITY_EXCLUDE_DETAILS
        if (Unity.CurrentDetail1)
        {
            UnityPrint(UnityStrDetail1Name);
            UnityPrint(Unity.CurrentDetail1);
            if (Unity.CurrentDetail2)
            {
                UnityPrint(UnityStrDetail2Name);
                UnityPrint(Unity.CurrentDetail2);
            }
            UnityPrint(UnityStrSpacer);
        }
#endif
        UnityPrint(msg);
    }
}

/*-----------------------------------------------*/
static void UnityPrintExpectedAndActualStrings(const char* expected, const char* actual)
{
    UnityPrint(UnityStrExpected);
    if (expected != NULL)
    {
        UNITY_OUTPUT_CHAR('\'');
        UnityPrint(expected);
        UNITY_OUTPUT_CHAR('\'');
    }
    else
    {
        UnityPrint(UnityStrNull);
    }
    UnityPrint(UnityStrWas);
    if (actual != NULL)
    {
        UNITY_OUTPUT_CHAR('\'');
        UnityPrint(actual);
        UNITY_OUTPUT_CHAR('\'');
    }
    else
    {
        UnityPrint(UnityStrNull);
    }
}

/*-----------------------------------------------*/
static void UnityPrintExpectedAndActualStringsLen(const char* expected,
                                                  const char* actual,
                                                  const UNITY_UINT32 length)
{
    UnityPrint(UnityStrExpected);
    if (expected != NULL)
    {
        UNITY_OUTPUT_CHAR('\'');
        UnityPrintLen(expected, length);
        UNITY_OUTPUT_CHAR('\'');
    }
    else
    {
        UnityPrint(UnityStrNull);
    }
    UnityPrint(UnityStrWas);
    if (actual != NULL)
    {
        UNITY_OUTPUT_CHAR('\'');
        UnityPrintLen(actual, length);
        UNITY_OUTPUT_CHAR('\'');
    }
    else
    {
        UnityPrint(UnityStrNull);
    }
}

/*-----------------------------------------------
 * Assertion & Control Helpers
 *-----------------------------------------------*/

/*-----------------------------------------------*/
static int UnityIsOneArrayNull(UNITY_INTERNAL_PTR expected,
                               UNITY_INTERNAL_PTR actual,
                               const UNITY_LINE_TYPE lineNumber,
                               const char* msg)
{
    /* Both are NULL or same pointer */
    if (expected == actual) { return 0; }

    /* print and return true if just expected is NULL */
    if (expected == NULL)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrNullPointerForExpected);
        UnityAddMsgIfSpecified(msg);
        return 1;
    }

    /* print and return true if just actual is NULL */
    if (actual == NULL)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrNullPointerForActual);
        UnityAddMsgIfSpecified(msg);
        return 1;
    }

    return 0; /* return false if neither is NULL */
}

/*-----------------------------------------------
 * Assertion Functions
 *-----------------------------------------------*/

/*-----------------------------------------------*/
void UnityAssertBits(const UNITY_INT mask,
                     const UNITY_INT expected,
                     const UNITY_INT actual,
                     const char* msg,
                     const UNITY_LINE_TYPE lineNumber)
{
    RETURN_IF_FAIL_OR_IGNORE;

    if ((mask & expected) != (mask & actual))
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrExpected);
        UnityPrintMask((UNITY_UINT)mask, (UNITY_UINT)expected);
        UnityPrint(UnityStrWas);
        UnityPrintMask((UNITY_UINT)mask, (UNITY_UINT)actual);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertEqualNumber(const UNITY_INT expected,
                            const UNITY_INT actual,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber,
                            const UNITY_DISPLAY_STYLE_T style)
{
    RETURN_IF_FAIL_OR_IGNORE;

    if (expected != actual)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrExpected);
        UnityPrintNumberByStyle(expected, style);
        UnityPrint(UnityStrWas);
        UnityPrintNumberByStyle(actual, style);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertGreaterOrLessOrEqualNumber(const UNITY_INT threshold,
                                           const UNITY_INT actual,
                                           const UNITY_COMPARISON_T compare,
                                           const char *msg,
                                           const UNITY_LINE_TYPE lineNumber,
                                           const UNITY_DISPLAY_STYLE_T style)
{
    int failed = 0;
    RETURN_IF_FAIL_OR_IGNORE;

    if ((threshold == actual) && (compare & UNITY_EQUAL_TO)) { return; }
    if ((threshold == actual))                               { failed = 1; }

    if ((style & UNITY_DISPLAY_RANGE_INT) == UNITY_DISPLAY_RANGE_INT)
    {
        if ((actual > threshold) && (compare & UNITY_SMALLER_THAN)) { failed = 1; }
        if ((actual < threshold) && (compare & UNITY_GREATER_THAN)) { failed = 1; }
    }
    else /* UINT or HEX */
    {
        if (((UNITY_UINT)actual > (UNITY_UINT)threshold) && (compare & UNITY_SMALLER_THAN)) { failed = 1; }
        if (((UNITY_UINT)actual < (UNITY_UINT)threshold) && (compare & UNITY_GREATER_THAN)) { failed = 1; }
    }

    if (failed)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrExpected);
        UnityPrintNumberByStyle(actual, style);
        if (compare & UNITY_GREATER_THAN) { UnityPrint(UnityStrGt);       }
        if (compare & UNITY_SMALLER_THAN) { UnityPrint(UnityStrLt);       }
        if (compare & UNITY_EQUAL_TO)     { UnityPrint(UnityStrOrEqual);  }
        if (compare == UNITY_NOT_EQUAL)   { UnityPrint(UnityStrNotEqual); }
        UnityPrintNumberByStyle(threshold, style);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

#define UnityPrintPointlessAndBail()       \
{                                          \
    UnityTestResultsFailBegin(lineNumber); \
    UnityPrint(UnityStrPointless);         \
    UnityAddMsgIfSpecified(msg);           \
    UNITY_FAIL_AND_BAIL; }

/*-----------------------------------------------*/
void UnityAssertEqualIntArray(UNITY_INTERNAL_PTR expected,
                              UNITY_INTERNAL_PTR actual,
                              const UNITY_UINT32 num_elements,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_DISPLAY_STYLE_T style,
                              const UNITY_FLAGS_T flags)
{
    UNITY_UINT32 elements  = num_elements;
    unsigned int length    = style & 0xF;
    unsigned int increment = 0;

    RETURN_IF_FAIL_OR_IGNORE;

    if (num_elements == 0)
    {
        UnityPrintPointlessAndBail();
    }

    if (expected == actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull(expected, actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    while ((elements > 0) && (elements--))
    {
        UNITY_INT expect_val;
        UNITY_INT actual_val;

        switch (length)
        {
            case 1:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT8*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT8*)actual;
                increment  = sizeof(UNITY_INT8);
                break;

            case 2:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT16*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT16*)actual;
                increment  = sizeof(UNITY_INT16);
                break;

#ifdef UNITY_SUPPORT_64
            case 8:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT64*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT64*)actual;
                increment  = sizeof(UNITY_INT64);
                break;
#endif

            default: /* default is length 4 bytes */
            case 4:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT32*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT32*)actual;
                increment  = sizeof(UNITY_INT32);
                length = 4;
                break;
        }

        if (expect_val != actual_val)
        {
            if ((style & UNITY_DISPLAY_RANGE_UINT) && (length < (UNITY_INT_WIDTH / 8)))
            {   /* For UINT, remove sign extension (padding 1's) from signed type casts above */
                UNITY_INT mask = 1;
                mask = (mask << 8 * length) - 1;
                expect_val &= mask;
                actual_val &= mask;
            }
            UnityTestResultsFailBegin(lineNumber);
            UnityPrint(UnityStrElement);
            UnityPrintNumberUnsigned(num_elements - elements - 1);
            UnityPrint(UnityStrExpected);
            UnityPrintNumberByStyle(expect_val, style);
            UnityPrint(UnityStrWas);
            UnityPrintNumberByStyle(actual_val, style);
            UnityAddMsgIfSpecified(msg);
            UNITY_FAIL_AND_BAIL;
        }
        /* Walk through array by incrementing the pointers */
        if (flags == UNITY_ARRAY_TO_ARRAY)
        {
            expected = (UNITY_INTERNAL_PTR)((const char*)expected + increment);
        }
        actual = (UNITY_INTERNAL_PTR)((const char*)actual + increment);
    }
}

/*-----------------------------------------------*/
#ifndef UNITY_EXCLUDE_FLOAT
/* Wrap this define in a function with variable types as float or double */
#define UNITY_FLOAT_OR_DOUBLE_WITHIN(delta, expected, actual, diff)                           \
    if (isinf(expected) && isinf(actual) && (((expected) < 0) == ((actual) < 0))) return 1;   \
    if (UNITY_NAN_CHECK) return 1;                                                            \
    (diff) = (actual) - (expected);                                                           \
    if ((diff) < 0) (diff) = -(diff);                                                         \
    if ((delta) < 0) (delta) = -(delta);                                                      \
    return !(isnan(diff) || isinf(diff) || ((diff) > (delta)))
    /* This first part of this condition will catch any NaN or Infinite values */
#ifndef UNITY_NAN_NOT_EQUAL_NAN
  #define UNITY_NAN_CHECK isnan(expected) && isnan(actual)
#else
  #define UNITY_NAN_CHECK 0
#endif

#ifndef UNITY_EXCLUDE_FLOAT_PRINT
  #define UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT(expected, actual) \
  {                                                               \
    UnityPrint(UnityStrExpected);                                 \
    UnityPrintFloat(expected);                                    \
    UnityPrint(UnityStrWas);                                      \
    UnityPrintFloat(actual); }
#else
  #define UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT(expected, actual) \
    UnityPrint(UnityStrDelta)
#endif /* UNITY_EXCLUDE_FLOAT_PRINT */

/*-----------------------------------------------*/
static int UnityFloatsWithin(UNITY_FLOAT delta, UNITY_FLOAT expected, UNITY_FLOAT actual)
{
    UNITY_FLOAT diff;
    UNITY_FLOAT_OR_DOUBLE_WITHIN(delta, expected, actual, diff);
}

/*-----------------------------------------------*/
void UnityAssertEqualFloatArray(UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* expected,
                                UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* actual,
                                const UNITY_UINT32 num_elements,
                                const char* msg,
                                const UNITY_LINE_TYPE lineNumber,
                                const UNITY_FLAGS_T flags)
{
    UNITY_UINT32 elements = num_elements;
    UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* ptr_expected = expected;
    UNITY_PTR_ATTRIBUTE const UNITY_FLOAT* ptr_actual = actual;

    RETURN_IF_FAIL_OR_IGNORE;

    if (elements == 0)
    {
        UnityPrintPointlessAndBail();
    }

    if (expected == actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull((UNITY_INTERNAL_PTR)expected, (UNITY_INTERNAL_PTR)actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    while (elements--)
    {
        if (!UnityFloatsWithin(*ptr_expected * UNITY_FLOAT_PRECISION, *ptr_expected, *ptr_actual))
        {
            UnityTestResultsFailBegin(lineNumber);
            UnityPrint(UnityStrElement);
            UnityPrintNumberUnsigned(num_elements - elements - 1);
            UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT((UNITY_DOUBLE)*ptr_expected, (UNITY_DOUBLE)*ptr_actual);
            UnityAddMsgIfSpecified(msg);
            UNITY_FAIL_AND_BAIL;
        }
        if (flags == UNITY_ARRAY_TO_ARRAY)
        {
            ptr_expected++;
        }
        ptr_actual++;
    }
}

/*-----------------------------------------------*/
void UnityAssertFloatsWithin(const UNITY_FLOAT delta,
                             const UNITY_FLOAT expected,
                             const UNITY_FLOAT actual,
                             const char* msg,
                             const UNITY_LINE_TYPE lineNumber)
{
    RETURN_IF_FAIL_OR_IGNORE;


    if (!UnityFloatsWithin(delta, expected, actual))
    {
        UnityTestResultsFailBegin(lineNumber);
        UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT((UNITY_DOUBLE)expected, (UNITY_DOUBLE)actual);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertFloatSpecial(const UNITY_FLOAT actual,
                             const char* msg,
                             const UNITY_LINE_TYPE lineNumber,
                             const UNITY_FLOAT_TRAIT_T style)
{
    const char* trait_names[] = {UnityStrInf, UnityStrNegInf, UnityStrNaN, UnityStrDet};
    UNITY_INT should_be_trait = ((UNITY_INT)style & 1);
    UNITY_INT is_trait        = !should_be_trait;
    UNITY_INT trait_index     = (UNITY_INT)(style >> 1);

    RETURN_IF_FAIL_OR_IGNORE;

    switch (style)
    {
        case UNITY_FLOAT_IS_INF:
        case UNITY_FLOAT_IS_NOT_INF:
            is_trait = isinf(actual) && (actual > 0);
            break;
        case UNITY_FLOAT_IS_NEG_INF:
        case UNITY_FLOAT_IS_NOT_NEG_INF:
            is_trait = isinf(actual) && (actual < 0);
            break;

        case UNITY_FLOAT_IS_NAN:
        case UNITY_FLOAT_IS_NOT_NAN:
            is_trait = isnan(actual) ? 1 : 0;
            break;

        case UNITY_FLOAT_IS_DET: /* A determinate number is non infinite and not NaN. */
        case UNITY_FLOAT_IS_NOT_DET:
            is_trait = !isinf(actual) && !isnan(actual);
            break;

        default: /* including UNITY_FLOAT_INVALID_TRAIT */
            trait_index = 0;
            trait_names[0] = UnityStrInvalidFloatTrait;
            break;
    }

    if (is_trait != should_be_trait)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrExpected);
        if (!should_be_trait)
        {
            UnityPrint(UnityStrNot);
        }
        UnityPrint(trait_names[trait_index]);
        UnityPrint(UnityStrWas);
#ifndef UNITY_EXCLUDE_FLOAT_PRINT
        UnityPrintFloat((UNITY_DOUBLE)actual);
#else
        if (should_be_trait)
        {
            UnityPrint(UnityStrNot);
        }
        UnityPrint(trait_names[trait_index]);
#endif
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

#endif /* not UNITY_EXCLUDE_FLOAT */

/*-----------------------------------------------*/
#ifndef UNITY_EXCLUDE_DOUBLE
static int UnityDoublesWithin(UNITY_DOUBLE delta, UNITY_DOUBLE expected, UNITY_DOUBLE actual)
{
    UNITY_DOUBLE diff;
    UNITY_FLOAT_OR_DOUBLE_WITHIN(delta, expected, actual, diff);
}

/*-----------------------------------------------*/
void UnityAssertEqualDoubleArray(UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* expected,
                                 UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* actual,
                                 const UNITY_UINT32 num_elements,
                                 const char* msg,
                                 const UNITY_LINE_TYPE lineNumber,
                                 const UNITY_FLAGS_T flags)
{
    UNITY_UINT32 elements = num_elements;
    UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* ptr_expected = expected;
    UNITY_PTR_ATTRIBUTE const UNITY_DOUBLE* ptr_actual = actual;

    RETURN_IF_FAIL_OR_IGNORE;

    if (elements == 0)
    {
        UnityPrintPointlessAndBail();
    }

    if (expected == actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull((UNITY_INTERNAL_PTR)expected, (UNITY_INTERNAL_PTR)actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    while (elements--)
    {
        if (!UnityDoublesWithin(*ptr_expected * UNITY_DOUBLE_PRECISION, *ptr_expected, *ptr_actual))
        {
            UnityTestResultsFailBegin(lineNumber);
            UnityPrint(UnityStrElement);
            UnityPrintNumberUnsigned(num_elements - elements - 1);
            UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT(*ptr_expected, *ptr_actual);
            UnityAddMsgIfSpecified(msg);
            UNITY_FAIL_AND_BAIL;
        }
        if (flags == UNITY_ARRAY_TO_ARRAY)
        {
            ptr_expected++;
        }
        ptr_actual++;
    }
}

/*-----------------------------------------------*/
void UnityAssertDoublesWithin(const UNITY_DOUBLE delta,
                              const UNITY_DOUBLE expected,
                              const UNITY_DOUBLE actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber)
{
    RETURN_IF_FAIL_OR_IGNORE;

    if (!UnityDoublesWithin(delta, expected, actual))
    {
        UnityTestResultsFailBegin(lineNumber);
        UNITY_PRINT_EXPECTED_AND_ACTUAL_FLOAT(expected, actual);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertDoubleSpecial(const UNITY_DOUBLE actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_FLOAT_TRAIT_T style)
{
    const char* trait_names[] = {UnityStrInf, UnityStrNegInf, UnityStrNaN, UnityStrDet};
    UNITY_INT should_be_trait = ((UNITY_INT)style & 1);
    UNITY_INT is_trait        = !should_be_trait;
    UNITY_INT trait_index     = (UNITY_INT)(style >> 1);

    RETURN_IF_FAIL_OR_IGNORE;

    switch (style)
    {
        case UNITY_FLOAT_IS_INF:
        case UNITY_FLOAT_IS_NOT_INF:
            is_trait = isinf(actual) && (actual > 0);
            break;
        case UNITY_FLOAT_IS_NEG_INF:
        case UNITY_FLOAT_IS_NOT_NEG_INF:
            is_trait = isinf(actual) && (actual < 0);
            break;

        case UNITY_FLOAT_IS_NAN:
        case UNITY_FLOAT_IS_NOT_NAN:
            is_trait = isnan(actual) ? 1 : 0;
            break;

        case UNITY_FLOAT_IS_DET: /* A determinate number is non infinite and not NaN. */
        case UNITY_FLOAT_IS_NOT_DET:
            is_trait = !isinf(actual) && !isnan(actual);
            break;

        default: /* including UNITY_FLOAT_INVALID_TRAIT */
            trait_index = 0;
            trait_names[0] = UnityStrInvalidFloatTrait;
            break;
    }

    if (is_trait != should_be_trait)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrExpected);
        if (!should_be_trait)
        {
            UnityPrint(UnityStrNot);
        }
        UnityPrint(trait_names[trait_index]);
        UnityPrint(UnityStrWas);
#ifndef UNITY_EXCLUDE_FLOAT_PRINT
        UnityPrintFloat(actual);
#else
        if (should_be_trait)
        {
            UnityPrint(UnityStrNot);
        }
        UnityPrint(trait_names[trait_index]);
#endif
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

#endif /* not UNITY_EXCLUDE_DOUBLE */

/*-----------------------------------------------*/
void UnityAssertNumbersWithin(const UNITY_UINT delta,
                              const UNITY_INT expected,
                              const UNITY_INT actual,
                              const char* msg,
                              const UNITY_LINE_TYPE lineNumber,
                              const UNITY_DISPLAY_STYLE_T style)
{
    RETURN_IF_FAIL_OR_IGNORE;

    if ((style & UNITY_DISPLAY_RANGE_INT) == UNITY_DISPLAY_RANGE_INT)
    {
        if (actual > expected)
        {
            Unity.CurrentTestFailed = (((UNITY_UINT)actual - (UNITY_UINT)expected) > delta);
        }
        else
        {
            Unity.CurrentTestFailed = (((UNITY_UINT)expected - (UNITY_UINT)actual) > delta);
        }
    }
    else
    {
        if ((UNITY_UINT)actual > (UNITY_UINT)expected)
        {
            Unity.CurrentTestFailed = (((UNITY_UINT)actual - (UNITY_UINT)expected) > delta);
        }
        else
        {
            Unity.CurrentTestFailed = (((UNITY_UINT)expected - (UNITY_UINT)actual) > delta);
        }
    }

    if (Unity.CurrentTestFailed)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrint(UnityStrDelta);
        UnityPrintNumberByStyle((UNITY_INT)delta, style);
        UnityPrint(UnityStrExpected);
        UnityPrintNumberByStyle(expected, style);
        UnityPrint(UnityStrWas);
        UnityPrintNumberByStyle(actual, style);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertNumbersArrayWithin(const UNITY_UINT delta,
                                   UNITY_INTERNAL_PTR expected,
                                   UNITY_INTERNAL_PTR actual,
                                   const UNITY_UINT32 num_elements,
                                   const char* msg,
                                   const UNITY_LINE_TYPE lineNumber,
                                   const UNITY_DISPLAY_STYLE_T style,
                                   const UNITY_FLAGS_T flags)
{
    UNITY_UINT32 elements = num_elements;
    unsigned int length   = style & 0xF;
    unsigned int increment = 0;

    RETURN_IF_FAIL_OR_IGNORE;

    if (num_elements == 0)
    {
        UnityPrintPointlessAndBail();
    }

    if (expected == actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull(expected, actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    while ((elements > 0) && (elements--))
    {
        UNITY_INT expect_val;
        UNITY_INT actual_val;

        switch (length)
        {
            case 1:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT8*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT8*)actual;
                increment  = sizeof(UNITY_INT8);
                break;

            case 2:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT16*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT16*)actual;
                increment  = sizeof(UNITY_INT16);
                break;

#ifdef UNITY_SUPPORT_64
            case 8:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT64*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT64*)actual;
                increment  = sizeof(UNITY_INT64);
                break;
#endif

            default: /* default is length 4 bytes */
            case 4:
                expect_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT32*)expected;
                actual_val = *(UNITY_PTR_ATTRIBUTE const UNITY_INT32*)actual;
                increment  = sizeof(UNITY_INT32);
                length = 4;
                break;
        }

        if ((style & UNITY_DISPLAY_RANGE_INT) == UNITY_DISPLAY_RANGE_INT)
        {
            if (actual_val > expect_val)
            {
                Unity.CurrentTestFailed = (((UNITY_UINT)actual_val - (UNITY_UINT)expect_val) > delta);
            }
            else
            {
                Unity.CurrentTestFailed = (((UNITY_UINT)expect_val - (UNITY_UINT)actual_val) > delta);
            }
        }
        else
        {
            if ((UNITY_UINT)actual_val > (UNITY_UINT)expect_val)
            {
                Unity.CurrentTestFailed = (((UNITY_UINT)actual_val - (UNITY_UINT)expect_val) > delta);
            }
            else
            {
                Unity.CurrentTestFailed = (((UNITY_UINT)expect_val - (UNITY_UINT)actual_val) > delta);
            }
        }

        if (Unity.CurrentTestFailed)
        {
            if ((style & UNITY_DISPLAY_RANGE_UINT) && (length < (UNITY_INT_WIDTH / 8)))
            {   /* For UINT, remove sign extension (padding 1's) from signed type casts above */
                UNITY_INT mask = 1;
                mask = (mask << 8 * length) - 1;
                expect_val &= mask;
                actual_val &= mask;
            }
            UnityTestResultsFailBegin(lineNumber);
            UnityPrint(UnityStrDelta);
            UnityPrintNumberByStyle((UNITY_INT)delta, style);
            UnityPrint(UnityStrElement);
            UnityPrintNumberUnsigned(num_elements - elements - 1);
            UnityPrint(UnityStrExpected);
            UnityPrintNumberByStyle(expect_val, style);
            UnityPrint(UnityStrWas);
            UnityPrintNumberByStyle(actual_val, style);
            UnityAddMsgIfSpecified(msg);
            UNITY_FAIL_AND_BAIL;
        }
        /* Walk through array by incrementing the pointers */
        if (flags == UNITY_ARRAY_TO_ARRAY)
        {
            expected = (UNITY_INTERNAL_PTR)((const char*)expected + increment);
        }
        actual = (UNITY_INTERNAL_PTR)((const char*)actual + increment);
    }
}

/*-----------------------------------------------*/
void UnityAssertEqualString(const char* expected,
                            const char* actual,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber)
{
    UNITY_UINT32 i;

    RETURN_IF_FAIL_OR_IGNORE;

    /* if both pointers not null compare the strings */
    if (expected && actual)
    {
        for (i = 0; expected[i] || actual[i]; i++)
        {
            if (expected[i] != actual[i])
            {
                Unity.CurrentTestFailed = 1;
                break;
            }
        }
    }
    else
    { /* handle case of one pointers being null (if both null, test should pass) */
        if (expected != actual)
        {
            Unity.CurrentTestFailed = 1;
        }
    }

    if (Unity.CurrentTestFailed)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrintExpectedAndActualStrings(expected, actual);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertEqualStringLen(const char* expected,
                               const char* actual,
                               const UNITY_UINT32 length,
                               const char* msg,
                               const UNITY_LINE_TYPE lineNumber)
{
    UNITY_UINT32 i;

    RETURN_IF_FAIL_OR_IGNORE;

    /* if both pointers not null compare the strings */
    if (expected && actual)
    {
        for (i = 0; (i < length) && (expected[i] || actual[i]); i++)
        {
            if (expected[i] != actual[i])
            {
                Unity.CurrentTestFailed = 1;
                break;
            }
        }
    }
    else
    { /* handle case of one pointers being null (if both null, test should pass) */
        if (expected != actual)
        {
            Unity.CurrentTestFailed = 1;
        }
    }

    if (Unity.CurrentTestFailed)
    {
        UnityTestResultsFailBegin(lineNumber);
        UnityPrintExpectedAndActualStringsLen(expected, actual, length);
        UnityAddMsgIfSpecified(msg);
        UNITY_FAIL_AND_BAIL;
    }
}

/*-----------------------------------------------*/
void UnityAssertEqualStringArray(UNITY_INTERNAL_PTR expected,
                                 const char** actual,
                                 const UNITY_UINT32 num_elements,
                                 const char* msg,
                                 const UNITY_LINE_TYPE lineNumber,
                                 const UNITY_FLAGS_T flags)
{
    UNITY_UINT32 i = 0;
    UNITY_UINT32 j = 0;
    const char* expd = NULL;
    const char* act = NULL;

    RETURN_IF_FAIL_OR_IGNORE;

    /* if no elements, it's an error */
    if (num_elements == 0)
    {
        UnityPrintPointlessAndBail();
    }

    if ((const void*)expected == (const void*)actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull((UNITY_INTERNAL_PTR)expected, (UNITY_INTERNAL_PTR)actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    if (flags != UNITY_ARRAY_TO_ARRAY)
    {
        expd = (const char*)expected;
    }

    do
    {
        act = actual[j];
        if (flags == UNITY_ARRAY_TO_ARRAY)
        {
            expd = ((const char* const*)expected)[j];
        }

        /* if both pointers not null compare the strings */
        if (expd && act)
        {
            for (i = 0; expd[i] || act[i]; i++)
            {
                if (expd[i] != act[i])
                {
                    Unity.CurrentTestFailed = 1;
                    break;
                }
            }
        }
        else
        { /* handle case of one pointers being null (if both null, test should pass) */
            if (expd != act)
            {
                Unity.CurrentTestFailed = 1;
            }
        }

        if (Unity.CurrentTestFailed)
        {
            UnityTestResultsFailBegin(lineNumber);
            if (num_elements > 1)
            {
                UnityPrint(UnityStrElement);
                UnityPrintNumberUnsigned(j);
            }
            UnityPrintExpectedAndActualStrings(expd, act);
            UnityAddMsgIfSpecified(msg);
            UNITY_FAIL_AND_BAIL;
        }
    } while (++j < num_elements);
}

/*-----------------------------------------------*/
void UnityAssertEqualMemory(UNITY_INTERNAL_PTR expected,
                            UNITY_INTERNAL_PTR actual,
                            const UNITY_UINT32 length,
                            const UNITY_UINT32 num_elements,
                            const char* msg,
                            const UNITY_LINE_TYPE lineNumber,
                            const UNITY_FLAGS_T flags)
{
    UNITY_PTR_ATTRIBUTE const unsigned char* ptr_exp = (UNITY_PTR_ATTRIBUTE const unsigned char*)expected;
    UNITY_PTR_ATTRIBUTE const unsigned char* ptr_act = (UNITY_PTR_ATTRIBUTE const unsigned char*)actual;
    UNITY_UINT32 elements = num_elements;
    UNITY_UINT32 bytes;

    RETURN_IF_FAIL_OR_IGNORE;

    if ((elements == 0) || (length == 0))
    {
        UnityPrintPointlessAndBail();
    }

    if (expected == actual)
    {
        return; /* Both are NULL or same pointer */
    }

    if (UnityIsOneArrayNull(expected, actual, lineNumber, msg))
    {
        UNITY_FAIL_AND_BAIL;
    }

    while (elements--)
    {
        bytes = length;
        while (bytes--)
        {
            if (*ptr_exp != *ptr_act)
            {
                UnityTestResultsFailBegin(lineNumber);
                UnityPrint(UnityStrMemory);
                if (num_elements > 1)
                {
                    UnityPrint(UnityStrElement);
                    UnityPrintNumberUnsigned(num_elements - elements - 1);
                }
                UnityPrint(UnityStrByte);
                UnityPrintNumberUnsigned(length - bytes - 1);
                UnityPrint(UnityStrExpected);
                UnityPrintNumberByStyle(*ptr_exp, UNITY_DISPLAY_STYLE_HEX8);
                UnityPrint(UnityStrWas);
                UnityPrintNumberByStyle(*ptr_act, UNITY_DISPLAY_STYLE_HEX8);
                UnityAddMsgIfSpecified(msg);
                UNITY_FAIL_AND_BAIL;
            }
            ptr_exp++;
            ptr_act++;
        }
        if (flags == UNITY_ARRAY_TO_VAL)
        {
            ptr_exp = (UNITY_PTR_ATTRIBUTE const unsigned char*)expected;
        }
    }
}

/*-----------------------------------------------*/

static union
{
    UNITY_INT8 i8;
    UNITY_INT16 i16;
    UNITY_INT32 i32;
#ifdef UNITY_SUPPORT_64
    UNITY_INT64 i64;
#endif
#ifndef UNITY_EXCLUDE_FLOAT
    float f;
#endif
#ifndef UNITY_EXCLUDE_DOUBLE
    double d;
#endif
} UnityQuickCompare;

UNITY_INTERNAL_PTR UnityNumToPtr(const UNITY_INT num, const UNITY_UINT8 size)
{
    switch(size)
    {
        case 1:
            UnityQuickCompare.i8 = (UNITY_INT8)num;
            return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.i8);

        case 2:
            UnityQuickCompare.i16 = (UNITY_INT16)num;
            return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.i16);

#ifdef UNITY_SUPPORT_64
        case 8:
            UnityQuickCompare.i64 = (UNITY_INT64)num;
            return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.i64);
#endif

        default: /* 4 bytes */
            UnityQuickCompare.i32 = (UNITY_INT32)num;
            return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.i32);
    }
}

#ifndef UNITY_EXCLUDE_FLOAT
/*-----------------------------------------------*/
UNITY_INTERNAL_PTR UnityFloatToPtr(const float num)
{
    UnityQuickCompare.f = num;
    return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.f);
}
#endif

#ifndef UNITY_EXCLUDE_DOUBLE
/*-----------------------------------------------*/
UNITY_INTERNAL_PTR UnityDoubleToPtr(const double num)
{
    UnityQuickCompare.d = num;
    return (UNITY_INTERNAL_PTR)(&UnityQuickCompare.d);
}
#endif

/*-----------------------------------------------
 * printf helper function
 *-----------------------------------------------*/
#ifdef UNITY_INCLUDE_PRINT_FORMATTED
static void UnityPrintFVA(const char* format, va_list va)
{
    const char* pch = format;
    if (pch != NULL)
    {
        while (*pch)
        {
            /* format identification character */
            if (*pch == '%')
            {
                pch++;

                if (pch != NULL)
                {
                    switch (*pch)
                    {
                        case 'd':
                        case 'i':
                            {
                                const int number = va_arg(va, int);
                                UnityPrintNumber((UNITY_INT)number);
                                break;
                            }
#ifndef UNITY_EXCLUDE_FLOAT_PRINT
                        case 'f':
                        case 'g':
                            {
                                const double number = va_arg(va, double);
                                UnityPrintFloat((UNITY_DOUBLE)number);
                                break;
                            }
#endif
                        case 'u':
                            {
                                const unsigned int number = va_arg(va, unsigned int);
                                UnityPrintNumberUnsigned((UNITY_UINT)number);
                                break;
                            }
                        case 'b':
                            {
                                const unsigned int number = va_arg(va, unsigned int);
                                const UNITY_UINT mask = (UNITY_UINT)0 - (UNITY_UINT)1;
                                UNITY_OUTPUT_CHAR('0');
                                UNITY_OUTPUT_CHAR('b');
                                UnityPrintMask(mask, (UNITY_UINT)number);
                                break;
                            }
                        case 'x':
                        case 'X':
                        case 'p':
                            {
                                const unsigned int number = va_arg(va, unsigned int);
                                UNITY_OUTPUT_CHAR('0');
                                UNITY_OUTPUT_CHAR('x');
                                UnityPrintNumberHex((UNITY_UINT)number, 8);
                                break;
                            }
                        case 'c':
                            {
                                const int ch = va_arg(va, int);
                                UnityPrintChar((const char *)&ch);
                                break;
                            }
                        case 's':
                            {
                                const char * string = va_arg(va, const char *);
                                UnityPrint(string);
                                break;
                            }
                        case '%':
                            {
                                UnityPrintChar(pch);
                                break;
                            }
                        default:
                            {
                                /* print the unknown format character */
                                UNITY_OUTPUT_CHAR('%');
                                UnityPrintChar(pch);
                                break;
                            }
                    }
                }
            }
#ifdef UNITY_OUTPUT_COLOR
            /* print ANSI escape code */
            else if ((*pch == 27) && (*(pch + 1) == '['))
            {
                pch += UnityPrintAnsiEscapeString(pch);
                continue;
            }
#endif
            else if (*pch == '\n')
            {
                UNITY_PRINT_EOL();
            }
            else
            {
                UnityPrintChar(pch);
            }

            pch++;
        }
    }
}

void UnityPrintF(const UNITY_LINE_TYPE line, const char* format, ...)
{
    UnityTestResultsBegin(Unity.TestFile, line);
    UnityPrint("INFO");
    if(format != NULL)
    {
        UnityPrint(": ");
        va_list va;
        va_start(va, format);
        UnityPrintFVA(format, va);
        va_end(va);
    }
    UNITY_PRINT_EOL();
}
#endif /* ! UNITY_INCLUDE_PRINT_FORMATTED */


/*-----------------------------------------------
 * Control Functions
 *-----------------------------------------------*/

/*-----------------------------------------------*/
void UnityFail(const char* msg, const UNITY_LINE_TYPE line)
{
    RETURN_IF_FAIL_OR_IGNORE;

    UnityTestResultsBegin(Unity.TestFile, line);
    UnityPrint(UnityStrFail);
    if (msg != NULL)
    {
        UNITY_OUTPUT_CHAR(':');

#ifdef UNITY_PRINT_TEST_CONTEXT
        UNITY_PRINT_TEST_CONTEXT();
#endif
#ifndef UNITY_EXCLUDE_DETAILS
        if (Unity.CurrentDetail1)
        {
            UnityPrint(UnityStrDetail1Name);
            UnityPrint(Unity.CurrentDetail1);
            if (Unity.CurrentDetail2)
            {
                UnityPrint(UnityStrDetail2Name);
                UnityPrint(Unity.CurrentDetail2);
            }
            UnityPrint(UnityStrSpacer);
        }
#endif
        if (msg[0] != ' ')
        {
            UNITY_OUTPUT_CHAR(' ');
        }
        UnityPrint(msg);
    }

    UNITY_FAIL_AND_BAIL;
}

/*-----------------------------------------------*/
void UnityIgnore(const char* msg, const UNITY_LINE_TYPE line)
{
    RETURN_IF_FAIL_OR_IGNORE;

    UnityTestResultsBegin(Unity.TestFile, line);
    UnityPrint(UnityStrIgnore);
    if (msg != NULL)
    {
        UNITY_OUTPUT_CHAR(':');
        UNITY_OUTPUT_CHAR(' ');
        UnityPrint(msg);
    }
    UNITY_IGNORE_AND_BAIL;
}

/*-----------------------------------------------*/
void UnityMessage(const char* msg, const UNITY_LINE_TYPE line)
{
    UnityTestResultsBegin(Unity.TestFile, line);
    UnityPrint("INFO");
    if (msg != NULL)
    {
      UNITY_OUTPUT_CHAR(':');
      UNITY_OUTPUT_CHAR(' ');
      UnityPrint(msg);
    }
    UNITY_PRINT_EOL();
}

/*-----------------------------------------------*/
/* If we have not defined our own test runner, then include our default test runner to make life easier */
#ifndef UNITY_SKIP_DEFAULT_RUNNER
void UnityDefaultTestRun(UnityTestFunction Func, const char* FuncName, const int FuncLineNum)
{
    Unity.CurrentTestName = FuncName;
    Unity.CurrentTestLineNumber = (UNITY_LINE_TYPE)FuncLineNum;
    Unity.NumberOfTests++;
    UNITY_CLR_DETAILS();
    UNITY_EXEC_TIME_START();
    if (TEST_PROTECT())
    {
        setUp();
        Func();
    }
    if (TEST_PROTECT())
    {
        tearDown();
    }
    UNITY_EXEC_TIME_STOP();
    UnityConcludeTest();
}
#endif

/*-----------------------------------------------*/
void UnitySetTestFile(const char* filename)
{
	Unity.TestFile = filename;
}

/*-----------------------------------------------*/
void UnityBegin(const char* filename)
{
    Unity.TestFile = filename;
    Unity.CurrentTestName = NULL;
    Unity.CurrentTestLineNumber = 0;
    Unity.NumberOfTests = 0;
    Unity.TestFailures = 0;
    Unity.TestIgnores = 0;
    Unity.CurrentTestFailed = 0;
    Unity.CurrentTestIgnored = 0;

    UNITY_CLR_DETAILS();
    UNITY_OUTPUT_START();
}

/*-----------------------------------------------*/
int UnityEnd(void)
{
    UNITY_PRINT_EOL();
    UnityPrint(UnityStrBreaker);
    UNITY_PRINT_EOL();
    UnityPrintNumber((UNITY_INT)(Unity.NumberOfTests));
    UnityPrint(UnityStrResultsTests);
    UnityPrintNumber((UNITY_INT)(Unity.TestFailures));
    UnityPrint(UnityStrResultsFailures);
    UnityPrintNumber((UNITY_INT)(Unity.TestIgnores));
    UnityPrint(UnityStrResultsIgnored);
    UNITY_PRINT_EOL();
    if (Unity.TestFailures == 0U)
    {
        UnityPrint(UnityStrOk);
    }
    else
    {
        UnityPrint(UnityStrFail);
#ifdef UNITY_DIFFERENTIATE_FINAL_FAIL
        UNITY_OUTPUT_CHAR('E'); UNITY_OUTPUT_CHAR('D');
#endif
    }
    UNITY_PRINT_EOL();
    UNITY_FLUSH_CALL();
    UNITY_OUTPUT_COMPLETE();
    return (int)(Unity.TestFailures);
}

/*-----------------------------------------------
 * Command Line Argument Support
 *-----------------------------------------------*/
#ifdef UNITY_USE_COMMAND_LINE_ARGS

char* UnityOptionIncludeNamed = NULL;
char* UnityOptionExcludeNamed = NULL;
int UnityVerbosity            = 1;

/*-----------------------------------------------*/
int UnityParseOptions(int argc, char** argv)
{
    int i;
    UnityOptionIncludeNamed = NULL;
    UnityOptionExcludeNamed = NULL;

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
                case 'l': /* list tests */
                    return -1;
                case 'n': /* include tests with name including this string */
                case 'f': /* an alias for -n */
                    if (argv[i][2] == '=')
                    {
                        UnityOptionIncludeNamed = &argv[i][3];
                    }
                    else if (++i < argc)
                    {
                        UnityOptionIncludeNamed = argv[i];
                    }
                    else
                    {
                        UnityPrint("ERROR: No Test String to Include Matches For");
                        UNITY_PRINT_EOL();
                        return 1;
                    }
                    break;
                case 'q': /* quiet */
                    UnityVerbosity = 0;
                    break;
                case 'v': /* verbose */
                    UnityVerbosity = 2;
                    break;
                case 'x': /* exclude tests with name including this string */
                    if (argv[i][2] == '=')
                    {
                        UnityOptionExcludeNamed = &argv[i][3];
                    }
                    else if (++i < argc)
                    {
                        UnityOptionExcludeNamed = argv[i];
                    }
                    else
                    {
                        UnityPrint("ERROR: No Test String to Exclude Matches For");
                        UNITY_PRINT_EOL();
                        return 1;
                    }
                    break;
                default:
                    UnityPrint("ERROR: Unknown Option ");
                    UNITY_OUTPUT_CHAR(argv[i][1]);
                    UNITY_PRINT_EOL();
                    return 1;
            }
        }
    }

    return 0;
}

/*-----------------------------------------------*/
int IsStringInBiggerString(const char* longstring, const char* shortstring)
{
    const char* lptr = longstring;
    const char* sptr = shortstring;
    const char* lnext = lptr;

    if (*sptr == '*')
    {
        return 1;
    }

    while (*lptr)
    {
        lnext = lptr + 1;

        /* If they current bytes match, go on to the next bytes */
        while (*lptr && *sptr && (*lptr == *sptr))
        {
            lptr++;
            sptr++;

            /* We're done if we match the entire string or up to a wildcard */
            if (*sptr == '*')
                return 1;
            if (*sptr == ',')
                return 1;
            if (*sptr == '"')
                return 1;
            if (*sptr == '\'')
                return 1;
            if (*sptr == ':')
                return 2;
            if (*sptr == 0)
                return 1;
        }

        /* Otherwise we start in the long pointer 1 character further and try again */
        lptr = lnext;
        sptr = shortstring;
    }

    return 0;
}

/*-----------------------------------------------*/
int UnityStringArgumentMatches(const char* str)
{
    int retval;
    const char* ptr1;
    const char* ptr2;
    const char* ptrf;

    /* Go through the options and get the substrings for matching one at a time */
    ptr1 = str;
    while (ptr1[0] != 0)
    {
        if ((ptr1[0] == '"') || (ptr1[0] == '\''))
        {
            ptr1++;
        }

        /* look for the start of the next partial */
        ptr2 = ptr1;
        ptrf = 0;
        do
        {
            ptr2++;
            if ((ptr2[0] == ':') && (ptr2[1] != 0) && (ptr2[0] != '\'') && (ptr2[0] != '"') && (ptr2[0] != ','))
            {
                ptrf = &ptr2[1];
            }
        } while ((ptr2[0] != 0) && (ptr2[0] != '\'') && (ptr2[0] != '"') && (ptr2[0] != ','));

        while ((ptr2[0] != 0) && ((ptr2[0] == ':') || (ptr2[0] == '\'') || (ptr2[0] == '"') || (ptr2[0] == ',')))
        {
            ptr2++;
        }

        /* done if complete filename match */
        retval = IsStringInBiggerString(Unity.TestFile, ptr1);
        if (retval == 1)
        {
            return retval;
        }

        /* done if testname match after filename partial match */
        if ((retval == 2) && (ptrf != 0))
        {
            if (IsStringInBiggerString(Unity.CurrentTestName, ptrf))
            {
                return 1;
            }
        }

        /* done if complete testname match */
        if (IsStringInBiggerString(Unity.CurrentTestName, ptr1) == 1)
        {
            return 1;
        }

        ptr1 = ptr2;
    }

    /* we couldn't find a match for any substrings */
    return 0;
}

/*-----------------------------------------------*/
int UnityTestMatches(void)
{
    /* Check if this test name matches the included test pattern */
    int retval;
    if (UnityOptionIncludeNamed)
    {
        retval = UnityStringArgumentMatches(UnityOptionIncludeNamed);
    }
    else
    {
        retval = 1;
    }

    /* Check if this test name matches the excluded test pattern */
    if (UnityOptionExcludeNamed)
    {
        if (UnityStringArgumentMatches(UnityOptionExcludeNamed))
        {
            retval = 0;
        }
    }

    return retval;
}

#endif /* UNITY_USE_COMMAND_LINE_ARGS */
/*-----------------------------------------------*/

