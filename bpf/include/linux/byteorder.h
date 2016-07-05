#ifndef _ASM_X86_BYTEORDER_H
#define _ASM_X86_BYTEORDER_H

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#include <linux/byteorder/little_endian.h>
#else
#include <linux/byteorder/big_endian.h>
#endif

#endif /* _ASM_X86_BYTEORDER_H */
