//go:build !linux

package rlimit

// RemoveMemlock is a no-op on platforms other than Linux.
func RemoveMemlock() error { return nil }
