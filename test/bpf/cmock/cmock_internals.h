/* ==========================================
    CMock Project - Automatic Mock Generation for C
    Copyright (c) 2007 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
========================================== */

#ifndef CMOCK_FRAMEWORK_INTERNALS_H
#define CMOCK_FRAMEWORK_INTERNALS_H

#include "unity.h"

/* These are constants that the generated mocks have access to */
extern const char* CMockStringOutOfMemory;
extern const char* CMockStringCalledMore;
extern const char* CMockStringCalledLess;
extern const char* CMockStringCalledEarly;
extern const char* CMockStringCalledLate;
extern const char* CMockStringCallOrder;
extern const char* CMockStringIgnPreExp;
extern const char* CMockStringPtrPreExp;
extern const char* CMockStringPtrIsNULL;
extern const char* CMockStringExpNULL;
extern const char* CMockStringMismatch;

/* define CMOCK_MEM_DYNAMIC to grab memory as needed with malloc
 * when you do that, CMOCK_MEM_SIZE is used for incremental size instead of total */
#ifdef CMOCK_MEM_STATIC
#undef CMOCK_MEM_DYNAMIC
#endif

#ifdef CMOCK_MEM_DYNAMIC
#include <stdlib.h>
#endif

/* this is used internally during pointer arithmetic. make sure this type is the same size as the target's pointer type */
#ifndef CMOCK_MEM_PTR_AS_INT
#ifdef UNITY_POINTER_WIDTH
#ifdef UNITY_INT_WIDTH
#if UNITY_POINTER_WIDTH == UNITY_INT_WIDTH
#define CMOCK_MEM_PTR_AS_INT unsigned int
#endif
#endif
#endif
#endif

#ifndef CMOCK_MEM_PTR_AS_INT
#ifdef UNITY_POINTER_WIDTH
#ifdef UNITY_LONG_WIDTH
#if UNITY_POINTER_WIDTH == UNITY_LONG_WIDTH
#define CMOCK_MEM_PTR_AS_INT unsigned long
#endif
#if UNITY_POINTER_WIDTH > UNITY_LONG_WIDTH
#define CMOCK_MEM_PTR_AS_INT unsigned long long
#endif
#endif
#endif
#endif

#ifndef CMOCK_MEM_PTR_AS_INT
#define CMOCK_MEM_PTR_AS_INT unsigned long
#endif

/* 0 for no alignment, 1 for 16-bit, 2 for 32-bit, 3 for 64-bit */
#ifndef CMOCK_MEM_ALIGN
  #ifdef UNITY_LONG_WIDTH
    #if (UNITY_LONG_WIDTH == 16)
      #define CMOCK_MEM_ALIGN (1)
    #elif (UNITY_LONG_WIDTH == 32)
      #define CMOCK_MEM_ALIGN (2)
    #elif (UNITY_LONG_WIDTH == 64)
      #define CMOCK_MEM_ALIGN (3)
    #else
      #define CMOCK_MEM_ALIGN (2)
    #endif
  #else
    #define CMOCK_MEM_ALIGN (2)
  #endif
#endif

/* amount of memory to allow cmock to use in its internal heap */
#ifndef CMOCK_MEM_SIZE
#define CMOCK_MEM_SIZE (32768)
#endif

/* automatically calculated defs for easier reading */
#define CMOCK_MEM_ALIGN_SIZE  (CMOCK_MEM_INDEX_TYPE)(1u << CMOCK_MEM_ALIGN)
#define CMOCK_MEM_ALIGN_MASK  (CMOCK_MEM_INDEX_TYPE)(CMOCK_MEM_ALIGN_SIZE - 1)
#define CMOCK_MEM_INDEX_SIZE  (CMOCK_MEM_INDEX_TYPE)(CMOCK_MEM_PTR_AS_INT)((sizeof(CMOCK_MEM_INDEX_TYPE) > CMOCK_MEM_ALIGN_SIZE) ? sizeof(CMOCK_MEM_INDEX_TYPE) : CMOCK_MEM_ALIGN_SIZE)


#endif /* end of CMOCK_FRAMEWORK_INTERNALS_H */

