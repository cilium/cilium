// Package perf allows interacting with Linux perf_events.
//
// BPF allows submitting custom perf_events to a ring-buffer set up
// by userspace. This is very useful to push things like packet samples
// from BPF to a daemon running in user space.
package perf
