package sys

// Pflag are bit flags used for polling. Values, including zero, should not
// be interpreted numerically. Instead, use by constants prefixed with 'POLL'.
//
// # Notes
//
//   - This is like `pollfd.events` flags for `poll` in POSIX. See
//     https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/poll.h.html
type Pflag uint32

// Only define bitflags we support and are needed by `poll_oneoff` in wasip1
// See https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#eventrwflags
const (
	// POLLIN is a read event.
	POLLIN Pflag = 1 << iota

	// POLLOUT is a write event.
	POLLOUT
)

// Pollable is implemented by custom readers that support polling for
// readiness. If a custom io.Reader passed to WithStdin implements this
// interface, poll_oneoff will use it for asynchronous I/O instead of
// returning "always ready".
//
// # Parameters
//
// The `flag` parameter determines which event to await, such as POLLIN,
// POLLOUT, or a combination like `POLLIN|POLLOUT`.
//
// The `timeoutMillis` parameter is how long to block for an event, or
// interrupted, in milliseconds. There are two special values:
//   - zero returns immediately
//   - any negative value blocks any amount of time
//
// # Results
//
// `ready` means there was data ready to read or written. False can mean no
// event was ready or `errno` is not zero.
//
// A zero `errno` is success. The below are expected otherwise:
//   - ENOSYS: the implementation does not support this function.
//   - ENOTSUP: the implementation does not support the flag combination.
//   - EINTR: the call was interrupted prior to an event.
type Pollable interface {
	Poll(flag Pflag, timeoutMillis int32) (ready bool, errno Errno)
}
