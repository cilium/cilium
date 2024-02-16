// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package rate provides a rate limiter to rate limit requests that can be
// burstable but they should only allowed N per a period defined.
// This package differs from the "golang.org/x/time/rate" package as it does not
// implement the token bucket algorithm.
package rate
