// Package ringbuf allows interacting with Linux BPF ring buffer.
//
// BPF allows submitting custom events to a BPF ring buffer map set up
// by userspace. This is very useful to push things like packet samples
// from BPF to a daemon running in user space.
package ringbuf
