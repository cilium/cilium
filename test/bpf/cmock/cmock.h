/* ==========================================
    CMock Project - Automatic Mock Generation for C
    Copyright (c) 2007 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
========================================== */

#ifndef CMOCK_FRAMEWORK_H
#define CMOCK_FRAMEWORK_H

#include "cmock_internals.h"

#define CMOCK_VERSION_MAJOR    2
#define CMOCK_VERSION_MINOR    5
#define CMOCK_VERSION_BUILD    4
#define CMOCK_VERSION          ((CMOCK_VERSION_MAJOR << 16) | (CMOCK_VERSION_MINOR << 8) | CMOCK_VERSION_BUILD)

/* should be big enough to index full range of CMOCK_MEM_MAX */
#ifndef CMOCK_MEM_INDEX_TYPE
#include <stddef.h>
#define CMOCK_MEM_INDEX_TYPE  size_t
#endif

#define CMOCK_GUTS_NONE   (0)

#if defined __GNUC__
#    define CMOCK_FUNCTION_ATTR(a) __attribute__((a))
#else
#    define CMOCK_FUNCTION_ATTR(a) /* ignore */
#endif

/*-------------------------------------------------------
 * Memory API
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemNew(CMOCK_MEM_INDEX_TYPE size);
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemChain(CMOCK_MEM_INDEX_TYPE root_index, CMOCK_MEM_INDEX_TYPE obj_index);
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemNext(CMOCK_MEM_INDEX_TYPE previous_item_index) CMOCK_FUNCTION_ATTR(pure);
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemEndOfChain(CMOCK_MEM_INDEX_TYPE root_index) CMOCK_FUNCTION_ATTR(pure);

void*                 CMock_Guts_GetAddressFor(CMOCK_MEM_INDEX_TYPE index) CMOCK_FUNCTION_ATTR(pure);

CMOCK_MEM_INDEX_TYPE CMock_Guts_MemBytesCapacity(void) CMOCK_FUNCTION_ATTR(const);
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemBytesFree(void) CMOCK_FUNCTION_ATTR(pure);
CMOCK_MEM_INDEX_TYPE  CMock_Guts_MemBytesUsed(void) CMOCK_FUNCTION_ATTR(pure);
void                  CMock_Guts_MemFreeAll(void);
void                  CMock_Guts_MemFreeFinal(void);

#endif /* end of CMOCK_FRAMEWORK_H */

