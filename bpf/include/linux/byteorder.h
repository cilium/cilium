#ifndef _ASM_X86_BYTEORDER_H
#define _ASM_X86_BYTEORDER_H

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#else
#include <linux/byteorder/big_endian.h>
#endif

#endif /* _ASM_X86_BYTEORDER_H */
