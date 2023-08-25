/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
/* Copyright Authors of Cilium */

#ifndef __ASM_BYTEORDER_H_
#define __ASM_BYTEORDER_H_

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include <linux/byteorder/little_endian.h>
#else
#include <linux/byteorder/big_endian.h>
#endif

#endif /* __ASM_BYTEORDER_H_ */
