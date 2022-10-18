/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __GHASH_H_
#define __GHASH_H_

#define U32MAX_DIV_GOLDEN_RATIO 0x9e3779b9

/* Calculate the Fibonacci hash of @key and return the @bits-wide value.
 *
 * h(k, n) is defined as n fractional bits of k / phi, where phi is the golden
 * ratio: phi = (sqrt(5) + 1) / 2
 *
 * It can be calculated as h(k, n) = [ {k / phi} * 2^n ], where square brackets
 * denote the integer part, and curly braces denote the fractional part. In
 * order to calculate it using integer arithmetic and to avoid an expensive
 * division, the formula can be multiplied and divided by 2^32, and 2^32 / phi
 * can be precalculated:
 *
 * h(k, n) = ((k * (2^32/phi)) % 2^32) / 2^(32-n)
 *         = ((k * A) % 2^32) / 2^(32-n)                                     (1)
 * (modulo 2^32 is implicit, and division by a power of two is a bit shift)
 *
 * Uniformity of the output values follows from theorem [1]. If we take the
 * interval [0, 1] and start adding points {1 / phi}, {2 / phi}, {3 / phi}, ...
 * (where curly braces denote the fractional part) into this interval, each new
 * point will split some subinterval of [0, 1] into two new subintervals. The
 * theorem claims that each new point splits the largest subinterval, and the
 * ratio between the new parts is not bigger than 2:1 (larger to smaller). This
 * means that the above sequence has low discrepancy, and the points are spread
 * uniformly enough over [0, 1]. Scaling up the interval [0, 1] to [0, 2^n] and
 * throwing away the fractional part, we get a hash function that spreads output
 * values uniformly for consecutive inputs.
 *
 * The completeness of the output range is guaranteed because in the actual
 * integer calculation GCD(A, 2^32) = 1, meaning that there is an inverse
 * element A^-1, such that (A * A^-1) mod 2^32 = 1, so for any value v of the
 * hash function there is a key k = (v * A^-1) mod 2^32, such that h(k) = v.
 *
 * Even though formula (1) resembles the formula for a multiplicative hash:
 * h(k) = (k * A) % m, where GCD(A, m) = 1,                                  (2)
 * formula (1) has an important difference. Instead of taking the least
 * significant bits of (k * A), it takes the most significant bits, hence it
 * doesn't discard the MSBs of the key, unlike formula (2). Such a modification
 * provides better distribution for keys with common lower bits, but it poses
 * more restrictions on A. Even some prime values of A become problematic, for
 * example, when A = 2576980349, 4 MSBs of (k * A) loop over 0x9, 0x3, 0xc, 0x6,
 * 0xf for k = 1 .. 1877171. Applicability of A = (2^32 / phi) is proven above
 * using theorem [1].
 *
 * [1]: Knuth. The Art of Computer Programming (2nd edition), vol. 3, sec. 6.4,
 * ex. 9 (page 550, solution on page 729).
 */
static __always_inline __u32 hash_32(__u32 key, __u32 bits)
{
	return (key * U32MAX_DIV_GOLDEN_RATIO) >> (32 - bits);
}

#endif /* __GHASH_H_ */
