/* ==========================================
    CMock Project - Automatic Mock Generation for C
    Copyright (c) 2007 Mike Karlesky, Mark VanderVoord, Greg Williams
    [Released under MIT License. Please refer to license.txt for details]
========================================== */

#include "cmock.h"

/* public constants to be used by mocks */
const char* CMockStringOutOfMemory = "CMock has run out of memory. Please allocate more.";
const char* CMockStringCalledMore  = "Called more times than expected.";
const char* CMockStringCalledLess  = "Called fewer times than expected.";
const char* CMockStringCalledEarly = "Called earlier than expected.";
const char* CMockStringCalledLate  = "Called later than expected.";
const char* CMockStringCallOrder   = "Called out of order.";
const char* CMockStringIgnPreExp   = "IgnoreArg called before Expect.";
const char* CMockStringPtrPreExp   = "ReturnThruPtr called before Expect.";
const char* CMockStringPtrIsNULL   = "Pointer is NULL.";
const char* CMockStringExpNULL     = "Expected NULL.";
const char* CMockStringMismatch    = "Function called with unexpected argument value.";

/* private variables */
#ifdef CMOCK_MEM_DYNAMIC
static unsigned char*         CMock_Guts_Buffer = NULL;
static CMOCK_MEM_INDEX_TYPE   CMock_Guts_BufferSize = CMOCK_MEM_ALIGN_SIZE;
static CMOCK_MEM_INDEX_TYPE   CMock_Guts_FreePtr = CMOCK_MEM_ALIGN_SIZE;
#else
static unsigned char          CMock_Guts_Buffer[CMOCK_MEM_SIZE + CMOCK_MEM_ALIGN_SIZE];
static CMOCK_MEM_INDEX_TYPE   CMock_Guts_BufferSize = CMOCK_MEM_SIZE + CMOCK_MEM_ALIGN_SIZE;
static CMOCK_MEM_INDEX_TYPE   CMock_Guts_FreePtr = CMOCK_MEM_ALIGN_SIZE;
#endif

/*-------------------------------------------------------
 * CMock_Guts_MemNew
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemNew(CMOCK_MEM_INDEX_TYPE size)
{
  CMOCK_MEM_INDEX_TYPE index;

  /* verify arguments valid (we must be allocating space for at least 1 byte, and the existing chain must be in memory somewhere) */
  if (size < 1)
    return CMOCK_GUTS_NONE;

  /* verify we have enough room */
  size = size + CMOCK_MEM_INDEX_SIZE;
  if (size & CMOCK_MEM_ALIGN_MASK)
    size = (size + CMOCK_MEM_ALIGN_MASK) & ~CMOCK_MEM_ALIGN_MASK;
  if ((CMock_Guts_BufferSize - CMock_Guts_FreePtr) < size)
  {
#ifndef CMOCK_MEM_DYNAMIC
    return CMOCK_GUTS_NONE; /* nothing we can do; our static buffer is out of memory */
#else
    /* our dynamic buffer does not have enough room; request more via realloc() */
    CMOCK_MEM_INDEX_TYPE new_buffersize = CMock_Guts_BufferSize + CMOCK_MEM_SIZE + size;
    unsigned char* new_buffer = realloc(CMock_Guts_Buffer, (size_t)new_buffersize);
    if (new_buffer == NULL)
      return CMOCK_GUTS_NONE; /* realloc() failed; out of memory */
    CMock_Guts_Buffer = new_buffer;
    CMock_Guts_BufferSize = new_buffersize;
#endif
  }

  /* determine where we're putting this new block, and init its pointer to be the end of the line */
  index = CMock_Guts_FreePtr + CMOCK_MEM_INDEX_SIZE;
  *(CMOCK_MEM_INDEX_TYPE*)(&CMock_Guts_Buffer[CMock_Guts_FreePtr]) = CMOCK_GUTS_NONE;
  CMock_Guts_FreePtr += size;

  return index;
}

/*-------------------------------------------------------
 * CMock_Guts_MemChain
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemChain(CMOCK_MEM_INDEX_TYPE root_index, CMOCK_MEM_INDEX_TYPE obj_index)
{
  CMOCK_MEM_INDEX_TYPE index;
  void* root;
  void* obj;
  void* next;

  if (root_index == CMOCK_GUTS_NONE)
  {
    /* if there is no root currently, we return this object as the root of the chain */
    return obj_index;
  }
  else
  {
    /* reject illegal nodes */
    if ((root_index < CMOCK_MEM_ALIGN_SIZE) || (root_index >= CMock_Guts_FreePtr))
    {
      return CMOCK_GUTS_NONE;
    }
    if ((obj_index < CMOCK_MEM_ALIGN_SIZE) || (obj_index >= CMock_Guts_FreePtr))
    {
      return CMOCK_GUTS_NONE;
    }

    root = (void*)(&CMock_Guts_Buffer[root_index]);
    obj  = (void*)(&CMock_Guts_Buffer[obj_index]);

    /* find the end of the existing chain and add us */
    next = root;
    do {
      index = *(CMOCK_MEM_INDEX_TYPE*)((CMOCK_MEM_PTR_AS_INT)next - CMOCK_MEM_INDEX_SIZE);
      if (index >= CMock_Guts_FreePtr)
        return CMOCK_GUTS_NONE;
      if (index > 0)
        next = (void*)(&CMock_Guts_Buffer[index]);
    } while (index > 0);
    *(CMOCK_MEM_INDEX_TYPE*)((CMOCK_MEM_PTR_AS_INT)next - CMOCK_MEM_INDEX_SIZE) = (CMOCK_MEM_INDEX_TYPE)((CMOCK_MEM_PTR_AS_INT)obj - (CMOCK_MEM_PTR_AS_INT)CMock_Guts_Buffer);
    return root_index;
  }
}

/*-------------------------------------------------------
 * CMock_Guts_MemNext
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemNext(CMOCK_MEM_INDEX_TYPE previous_item_index)
{
  CMOCK_MEM_INDEX_TYPE index;
  void* previous_item;

  /* There is nothing "next" if the pointer isn't from our buffer */
  if ((previous_item_index < CMOCK_MEM_ALIGN_SIZE) || (previous_item_index  >= CMock_Guts_FreePtr))
    return CMOCK_GUTS_NONE;
  previous_item = (void*)(&CMock_Guts_Buffer[previous_item_index]);

  /* if the pointer is good, then use it to look up the next index
   * (we know the first element always goes in zero, so NEXT must always be > 1) */
  index = *(CMOCK_MEM_INDEX_TYPE*)((CMOCK_MEM_PTR_AS_INT)previous_item - CMOCK_MEM_INDEX_SIZE);
  if ((index > 1) && (index < CMock_Guts_FreePtr))
    return index;
  else
    return CMOCK_GUTS_NONE;
}

/*-------------------------------------------------------
 * CMock_Guts_MemEndOfChain
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemEndOfChain(CMOCK_MEM_INDEX_TYPE root_index)
{
  CMOCK_MEM_INDEX_TYPE index = root_index;
  CMOCK_MEM_INDEX_TYPE next_index;

  for (next_index = root_index;
       next_index != CMOCK_GUTS_NONE;
       next_index = CMock_Guts_MemNext(index))
  {
    index = next_index;
  }

  return index;
}

/*-------------------------------------------------------
 * CMock_GetAddressFor
 *-------------------------------------------------------*/
void* CMock_Guts_GetAddressFor(CMOCK_MEM_INDEX_TYPE index)
{
  if ((index >= CMOCK_MEM_ALIGN_SIZE) && (index < CMock_Guts_FreePtr))
  {
    return (void*)(&CMock_Guts_Buffer[index]);
  }
  else
  {
    return NULL;
  }
}

/*-------------------------------------------------------
 * CMock_Guts_MemBytesCapacity
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemBytesCapacity(void)
{
  return (sizeof(CMock_Guts_Buffer) - CMOCK_MEM_ALIGN_SIZE);
}

/*-------------------------------------------------------
 * CMock_Guts_MemBytesFree
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemBytesFree(void)
{
  return CMock_Guts_BufferSize - CMock_Guts_FreePtr;
}

/*-------------------------------------------------------
 * CMock_Guts_MemBytesUsed
 *-------------------------------------------------------*/
CMOCK_MEM_INDEX_TYPE CMock_Guts_MemBytesUsed(void)
{
  return CMock_Guts_FreePtr - CMOCK_MEM_ALIGN_SIZE;
}

/*-------------------------------------------------------
 * CMock_Guts_MemFreeAll
 *-------------------------------------------------------*/
void CMock_Guts_MemFreeAll(void)
{
  CMock_Guts_FreePtr = CMOCK_MEM_ALIGN_SIZE; /* skip the very beginning */
}

/*-------------------------------------------------------
 * CMock_Guts_MemFreeFinal
 *-------------------------------------------------------*/
void CMock_Guts_MemFreeFinal(void)
{
  CMock_Guts_FreePtr = CMOCK_MEM_ALIGN_SIZE;
#ifdef CMOCK_MEM_DYNAMIC
  if (CMock_Guts_Buffer)
  {
    free(CMock_Guts_Buffer);
    CMock_Guts_Buffer = NULL;
  }
#endif
}


