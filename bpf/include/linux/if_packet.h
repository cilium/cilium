/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H

#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_USER		6		/* To user space	*/
#define PACKET_KERNEL		7		/* To kernel space	*/
/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/

#endif // __LINUX_IF_PACKET_H
