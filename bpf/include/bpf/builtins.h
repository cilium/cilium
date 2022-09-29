/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_BUILTINS__
#define __BPF_BUILTINS__

#include "compiler.h"

#ifndef lock_xadd
# define lock_xadd(P, V)	((void) __sync_fetch_and_add((P), (V)))
#endif

/* Unfortunately verifier forces aligned stack access while other memory
 * do not have to be aligned (map, pkt, etc). Mark those on the /stack/
 * for objects > 8 bytes in order to force-align such memcpy candidates
 * when we really need them to be aligned, this is not needed for objects
 * of size <= 8 bytes and in case of > 8 bytes /only/ when 8 byte is not
 * the natural object alignment (e.g. __u8 foo[12]).
 */
#define __align_stack_8		__aligned(8)

/* Memory iterators used below. */
#define __it_bwd(x, op) (x -= sizeof(__u##op))
#define __it_fwd(x, op) (x += sizeof(__u##op))

/* Memory operators used below. */
#define __it_set(a, op) (*(__u##op *)__it_bwd(a, op)) = 0
#define __it_xor(a, b, r, op) r |= (*(__u##op *)__it_bwd(a, op)) ^ (*(__u##op *)__it_bwd(b, op))
#define __it_mob(a, b, op) (*(__u##op *)__it_bwd(a, op)) = (*(__u##op *)__it_bwd(b, op))
#define __it_mof(a, b, op)				\
	do {						\
		*(__u##op *)a = *(__u##op *)b;		\
		__it_fwd(a, op); __it_fwd(b, op);	\
	} while (0)

static __always_inline __maybe_unused void
__bpf_memset_builtin(void *d, __u8 c, __u64 len)
{
	/* Everything non-zero or non-const (currently unsupported) as c
	 * gets handled here.
	 */
	__builtin_memset(d, c, len);
}

static __always_inline void __bpf_memzero(void *d, __u64 len)
{
#if __clang_major__ >= 10
	if (!__builtin_constant_p(len))
		__throw_build_bug();

	d += len;

	switch (len) {
	case 96:         __it_set(d, 64);
	case 88: jmp_88: __it_set(d, 64);
	case 80: jmp_80: __it_set(d, 64);
	case 72: jmp_72: __it_set(d, 64);
	case 64: jmp_64: __it_set(d, 64);
	case 56: jmp_56: __it_set(d, 64);
	case 48: jmp_48: __it_set(d, 64);
	case 40: jmp_40: __it_set(d, 64);
	case 32: jmp_32: __it_set(d, 64);
	case 24: jmp_24: __it_set(d, 64);
	case 16: jmp_16: __it_set(d, 64);
	case  8: jmp_8:  __it_set(d, 64);
		break;

	case 94: __it_set(d, 16); __it_set(d, 32); goto jmp_88;
	case 86: __it_set(d, 16); __it_set(d, 32); goto jmp_80;
	case 78: __it_set(d, 16); __it_set(d, 32); goto jmp_72;
	case 70: __it_set(d, 16); __it_set(d, 32); goto jmp_64;
	case 62: __it_set(d, 16); __it_set(d, 32); goto jmp_56;
	case 54: __it_set(d, 16); __it_set(d, 32); goto jmp_48;
	case 46: __it_set(d, 16); __it_set(d, 32); goto jmp_40;
	case 38: __it_set(d, 16); __it_set(d, 32); goto jmp_32;
	case 30: __it_set(d, 16); __it_set(d, 32); goto jmp_24;
	case 22: __it_set(d, 16); __it_set(d, 32); goto jmp_16;
	case 14: __it_set(d, 16); __it_set(d, 32); goto jmp_8;
	case  6: __it_set(d, 16); __it_set(d, 32);
		break;

	case 92: __it_set(d, 32); goto jmp_88;
	case 84: __it_set(d, 32); goto jmp_80;
	case 76: __it_set(d, 32); goto jmp_72;
	case 68: __it_set(d, 32); goto jmp_64;
	case 60: __it_set(d, 32); goto jmp_56;
	case 52: __it_set(d, 32); goto jmp_48;
	case 44: __it_set(d, 32); goto jmp_40;
	case 36: __it_set(d, 32); goto jmp_32;
	case 28: __it_set(d, 32); goto jmp_24;
	case 20: __it_set(d, 32); goto jmp_16;
	case 12: __it_set(d, 32); goto jmp_8;
	case  4: __it_set(d, 32);
		break;

	case 90: __it_set(d, 16); goto jmp_88;
	case 82: __it_set(d, 16); goto jmp_80;
	case 74: __it_set(d, 16); goto jmp_72;
	case 66: __it_set(d, 16); goto jmp_64;
	case 58: __it_set(d, 16); goto jmp_56;
	case 50: __it_set(d, 16); goto jmp_48;
	case 42: __it_set(d, 16); goto jmp_40;
	case 34: __it_set(d, 16); goto jmp_32;
	case 26: __it_set(d, 16); goto jmp_24;
	case 18: __it_set(d, 16); goto jmp_16;
	case 10: __it_set(d, 16); goto jmp_8;
	case  2: __it_set(d, 16);
		break;

	case  1: __it_set(d, 8);
		break;

	default:
		/* __builtin_memset() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__throw_build_bug();
	}
#else
	__bpf_memset_builtin(d, 0, len);
#endif
}

static __always_inline __maybe_unused void
__bpf_no_builtin_memset(void *d __maybe_unused, __u8 c __maybe_unused,
			__u64 len __maybe_unused)
{
	__throw_build_bug();
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memset	__bpf_no_builtin_memset

static __always_inline __nobuiltin("memset") void memset(void *d, int c,
							 __u64 len)
{
	if (__builtin_constant_p(len) && __builtin_constant_p(c) && c == 0)
		__bpf_memzero(d, len);
	else
		__bpf_memset_builtin(d, (__u8)c, len);
}

static __always_inline __maybe_unused void
__bpf_memcpy_builtin(void *d, const void *s, __u64 len)
{
	/* Explicit opt-in for __builtin_memcpy(). */
	__builtin_memcpy(d, s, len);
}

static __always_inline void __bpf_memcpy(void *d, const void *s, __u64 len)
{
#if __clang_major__ >= 10
	if (!__builtin_constant_p(len))
		__throw_build_bug();

	d += len;
	s += len;

	if (len > 1 && len % 2 == 1) {
		__it_mob(d, s, 8);
		len -= 1;
	}

	switch (len) {
	case 96:         __it_mob(d, s, 64);
	case 88: jmp_88: __it_mob(d, s, 64);
	case 80: jmp_80: __it_mob(d, s, 64);
	case 72: jmp_72: __it_mob(d, s, 64);
	case 64: jmp_64: __it_mob(d, s, 64);
	case 56: jmp_56: __it_mob(d, s, 64);
	case 48: jmp_48: __it_mob(d, s, 64);
	case 40: jmp_40: __it_mob(d, s, 64);
	case 32: jmp_32: __it_mob(d, s, 64);
	case 24: jmp_24: __it_mob(d, s, 64);
	case 16: jmp_16: __it_mob(d, s, 64);
	case  8: jmp_8:  __it_mob(d, s, 64);
		break;

	case 94: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_88;
	case 86: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_80;
	case 78: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_72;
	case 70: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_64;
	case 62: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_56;
	case 54: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_48;
	case 46: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_40;
	case 38: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_32;
	case 30: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_24;
	case 22: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_16;
	case 14: __it_mob(d, s, 16); __it_mob(d, s, 32); goto jmp_8;
	case  6: __it_mob(d, s, 16); __it_mob(d, s, 32);
		break;

	case 92: __it_mob(d, s, 32); goto jmp_88;
	case 84: __it_mob(d, s, 32); goto jmp_80;
	case 76: __it_mob(d, s, 32); goto jmp_72;
	case 68: __it_mob(d, s, 32); goto jmp_64;
	case 60: __it_mob(d, s, 32); goto jmp_56;
	case 52: __it_mob(d, s, 32); goto jmp_48;
	case 44: __it_mob(d, s, 32); goto jmp_40;
	case 36: __it_mob(d, s, 32); goto jmp_32;
	case 28: __it_mob(d, s, 32); goto jmp_24;
	case 20: __it_mob(d, s, 32); goto jmp_16;
	case 12: __it_mob(d, s, 32); goto jmp_8;
	case  4: __it_mob(d, s, 32);
		break;

	case 90: __it_mob(d, s, 16); goto jmp_88;
	case 82: __it_mob(d, s, 16); goto jmp_80;
	case 74: __it_mob(d, s, 16); goto jmp_72;
	case 66: __it_mob(d, s, 16); goto jmp_64;
	case 58: __it_mob(d, s, 16); goto jmp_56;
	case 50: __it_mob(d, s, 16); goto jmp_48;
	case 42: __it_mob(d, s, 16); goto jmp_40;
	case 34: __it_mob(d, s, 16); goto jmp_32;
	case 26: __it_mob(d, s, 16); goto jmp_24;
	case 18: __it_mob(d, s, 16); goto jmp_16;
	case 10: __it_mob(d, s, 16); goto jmp_8;
	case  2: __it_mob(d, s, 16);
		break;

	case  1: __it_mob(d, s, 8);
		break;

	default:
		/* __builtin_memcpy() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__throw_build_bug();
	}
#else
	__bpf_memcpy_builtin(d, s, len);
#endif
}

static __always_inline __maybe_unused void
__bpf_no_builtin_memcpy(void *d __maybe_unused, const void *s __maybe_unused,
			__u64 len __maybe_unused)
{
	__throw_build_bug();
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memcpy	__bpf_no_builtin_memcpy

static __always_inline __nobuiltin("memcpy") void memcpy(void *d, const void *s,
							 __u64 len)
{
	return __bpf_memcpy(d, s, len);
}

static __always_inline __maybe_unused __u64
__bpf_memcmp_builtin(const void *x, const void *y, __u64 len)
{
	/* Explicit opt-in for __builtin_memcmp(). We use the bcmp builtin
	 * here for two reasons: i) we only need to know equal or non-equal
	 * similar as in __bpf_memcmp(), and ii) if __bpf_memcmp() ends up
	 * selecting __bpf_memcmp_builtin(), clang generats a memcmp loop.
	 * That is, (*) -> __bpf_memcmp() -> __bpf_memcmp_builtin() ->
	 * __builtin_memcmp() -> memcmp() -> (*), meaning it will end up
	 * selecting our memcmp() from here. Remapping to __builtin_bcmp()
	 * breaks this loop and resolves both needs at once.
	 */
	return __builtin_bcmp(x, y, len);
}

static __always_inline __u64 __bpf_memcmp(const void *x, const void *y,
					  __u64 len)
{
#if __clang_major__ >= 10
	__u64 r = 0;

	if (!__builtin_constant_p(len))
		__throw_build_bug();

	x += len;
	y += len;

	if (len > 1 && len % 2 == 1) {
		__it_xor(x, y, r, 8);
		len -= 1;
	}

	switch (len) {
	case 72:         __it_xor(x, y, r, 64);
	case 64: jmp_64: __it_xor(x, y, r, 64);
	case 56: jmp_56: __it_xor(x, y, r, 64);
	case 48: jmp_48: __it_xor(x, y, r, 64);
	case 40: jmp_40: __it_xor(x, y, r, 64);
	case 32: jmp_32: __it_xor(x, y, r, 64);
	case 24: jmp_24: __it_xor(x, y, r, 64);
	case 16: jmp_16: __it_xor(x, y, r, 64);
	case  8: jmp_8:  __it_xor(x, y, r, 64);
		break;

	case 70: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_64;
	case 62: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_56;
	case 54: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_48;
	case 46: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_40;
	case 38: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_32;
	case 30: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_24;
	case 22: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_16;
	case 14: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32); goto jmp_8;
	case  6: __it_xor(x, y, r, 16); __it_xor(x, y, r, 32);
		break;

	case 68: __it_xor(x, y, r, 32); goto jmp_64;
	case 60: __it_xor(x, y, r, 32); goto jmp_56;
	case 52: __it_xor(x, y, r, 32); goto jmp_48;
	case 44: __it_xor(x, y, r, 32); goto jmp_40;
	case 36: __it_xor(x, y, r, 32); goto jmp_32;
	case 28: __it_xor(x, y, r, 32); goto jmp_24;
	case 20: __it_xor(x, y, r, 32); goto jmp_16;
	case 12: __it_xor(x, y, r, 32); goto jmp_8;
	case  4: __it_xor(x, y, r, 32);
		break;

	case 66: __it_xor(x, y, r, 16); goto jmp_64;
	case 58: __it_xor(x, y, r, 16); goto jmp_56;
	case 50: __it_xor(x, y, r, 16); goto jmp_48;
	case 42: __it_xor(x, y, r, 16); goto jmp_40;
	case 34: __it_xor(x, y, r, 16); goto jmp_32;
	case 26: __it_xor(x, y, r, 16); goto jmp_24;
	case 18: __it_xor(x, y, r, 16); goto jmp_16;
	case 10: __it_xor(x, y, r, 16); goto jmp_8;
	case  2: __it_xor(x, y, r, 16);
		break;

	case  1: __it_xor(x, y, r, 8);
		break;

	default:
		__throw_build_bug();
	}

	return r;
#else
	return __bpf_memcmp_builtin(x, y, len);
#endif
}

static __always_inline __maybe_unused __u64
__bpf_no_builtin_memcmp(const void *x __maybe_unused,
			const void *y __maybe_unused, __u64 len __maybe_unused)
{
	__throw_build_bug();
	return 0;
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memcmp	__bpf_no_builtin_memcmp

/* Modified for our needs in that we only return either zero (x and y
 * are equal) or non-zero (x and y are non-equal).
 */
static __always_inline __nobuiltin("memcmp") __u64 memcmp(const void *x,
							  const void *y,
							  __u64 len)
{
	return __bpf_memcmp(x, y, len);
}

static __always_inline __maybe_unused void
__bpf_memmove_builtin(void *d, const void *s, __u64 len)
{
	/* Explicit opt-in for __builtin_memmove(). */
	__builtin_memmove(d, s, len);
}

static __always_inline void __bpf_memmove_bwd(void *d, const void *s, __u64 len)
{
	/* Our internal memcpy implementation walks backwards by default. */
	__bpf_memcpy(d, s, len);
}

static __always_inline void __bpf_memmove_fwd(void *d, const void *s, __u64 len)
{
#if __clang_major__ >= 10
	if (!__builtin_constant_p(len))
		__throw_build_bug();

	switch (len) {
	case 96:         __it_mof(d, s, 64);
	case 88: jmp_88: __it_mof(d, s, 64);
	case 80: jmp_80: __it_mof(d, s, 64);
	case 72: jmp_72: __it_mof(d, s, 64);
	case 64: jmp_64: __it_mof(d, s, 64);
	case 56: jmp_56: __it_mof(d, s, 64);
	case 48: jmp_48: __it_mof(d, s, 64);
	case 40: jmp_40: __it_mof(d, s, 64);
	case 32: jmp_32: __it_mof(d, s, 64);
	case 24: jmp_24: __it_mof(d, s, 64);
	case 16: jmp_16: __it_mof(d, s, 64);
	case  8: jmp_8:  __it_mof(d, s, 64);
		break;

	case 94: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_88;
	case 86: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_80;
	case 78: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_72;
	case 70: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_64;
	case 62: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_56;
	case 54: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_48;
	case 46: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_40;
	case 38: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_32;
	case 30: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_24;
	case 22: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_16;
	case 14: __it_mof(d, s, 16); __it_mof(d, s, 32); goto jmp_8;
	case  6: __it_mof(d, s, 16); __it_mof(d, s, 32);
		break;

	case 92: __it_mof(d, s, 32); goto jmp_88;
	case 84: __it_mof(d, s, 32); goto jmp_80;
	case 76: __it_mof(d, s, 32); goto jmp_72;
	case 68: __it_mof(d, s, 32); goto jmp_64;
	case 60: __it_mof(d, s, 32); goto jmp_56;
	case 52: __it_mof(d, s, 32); goto jmp_48;
	case 44: __it_mof(d, s, 32); goto jmp_40;
	case 36: __it_mof(d, s, 32); goto jmp_32;
	case 28: __it_mof(d, s, 32); goto jmp_24;
	case 20: __it_mof(d, s, 32); goto jmp_16;
	case 12: __it_mof(d, s, 32); goto jmp_8;
	case  4: __it_mof(d, s, 32);
		break;

	case 90: __it_mof(d, s, 16); goto jmp_88;
	case 82: __it_mof(d, s, 16); goto jmp_80;
	case 74: __it_mof(d, s, 16); goto jmp_72;
	case 66: __it_mof(d, s, 16); goto jmp_64;
	case 58: __it_mof(d, s, 16); goto jmp_56;
	case 50: __it_mof(d, s, 16); goto jmp_48;
	case 42: __it_mof(d, s, 16); goto jmp_40;
	case 34: __it_mof(d, s, 16); goto jmp_32;
	case 26: __it_mof(d, s, 16); goto jmp_24;
	case 18: __it_mof(d, s, 16); goto jmp_16;
	case 10: __it_mof(d, s, 16); goto jmp_8;
	case  2: __it_mof(d, s, 16);
		break;

	case  1: __it_mof(d, s, 8);
		break;

	default:
		/* __builtin_memmove() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__throw_build_bug();
	}
#else
	__bpf_memmove_builtin(d, s, len);
#endif
}

static __always_inline __maybe_unused void
__bpf_no_builtin_memmove(void *d __maybe_unused, const void *s __maybe_unused,
			 __u64 len __maybe_unused)
{
	__throw_build_bug();
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memmove	__bpf_no_builtin_memmove

static __always_inline void __bpf_memmove(void *d, const void *s, __u64 len)
{
	/* Note, the forward walking memmove() might not work with on-stack data
	 * since we'll end up walking the memory unaligned even when __align_stack_8
	 * is set. Should not matter much since we'll use memmove() mostly or only
	 * on pkt data.
	 *
	 * Example with d, s, len = 12 bytes:
	 *   * __bpf_memmove_fwd() emits: mov_32 d[0],s[0]; mov_64 d[4],s[4]
	 *   * __bpf_memmove_bwd() emits: mov_32 d[8],s[8]; mov_64 d[0],s[0]
	 */
	if (d <= s)
		return __bpf_memmove_fwd(d, s, len);
	else
		return __bpf_memmove_bwd(d, s, len);
}

static __always_inline __nobuiltin("memmove") void memmove(void *d,
							   const void *s,
							   __u64 len)
{
	return __bpf_memmove(d, s, len);
}

#endif /* __BPF_BUILTINS__ */
