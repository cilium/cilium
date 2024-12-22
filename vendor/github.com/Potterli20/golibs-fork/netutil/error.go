package netutil

import (
	"fmt"

	"github.com/Potterli20/golibs-fork/errors"
)

// Errors
//
// TODO(a.garipov): Implement the errors.Iser interface and use errors.Is in
// tests to test the whole content of the errors.

const (
	// ErrNotAReversedIP is the underlying error returned from validation
	// functions when a domain name is not a full reversed IP address.
	ErrNotAReversedIP errors.Error = "not a full reversed ip address"

	// ErrNotAReversedSubnet is the underlying error returned from validation
	// functions when a domain name is not a valid reversed IP network.
	ErrNotAReversedSubnet errors.Error = "not a reversed ip network"
)

// AddrKind is a convenient alias for string describing the kind of address and
// used for error reporting.
type AddrKind = string

// Kinds of addresses for [AddrError].
const (
	AddrKindARPA       AddrKind = "arpa domain name"
	AddrKindCIDR       AddrKind = "cidr address"
	AddrKindHostPort   AddrKind = "hostport address"
	AddrKindIP         AddrKind = "ip address"
	AddrKindIPPort     AddrKind = "ipport address"
	AddrKindIPv4       AddrKind = "ipv4 address"
	AddrKindMAC        AddrKind = "mac address"
	AddrKindName       AddrKind = "hostname"
	AddrKindDomainName AddrKind = "domain name"
	AddrKindSRVName    AddrKind = "service domain name"
)

// AddrError is the underlying type of errors returned from validation
// functions when a domain name is invalid.
type AddrError struct {
	// Err is the underlying error, if any.
	Err error

	// Kind is the kind of address or address part.
	Kind AddrKind

	// Addr is the text of the invalid address.
	Addr string
}

// type check
var _ error = (*AddrError)(nil)

// Error implements the error interface for *AddrError.
func (err *AddrError) Error() (msg string) {
	if err.Err != nil {
		return fmt.Sprintf("bad %s %q: %s", err.Kind, err.Addr, err.Err)
	}

	return fmt.Sprintf("bad %s %q", err.Kind, err.Addr)
}

// type check
var _ errors.Wrapper = (*AddrError)(nil)

// Unwrap implements the [errors.Wrapper] interface for *AddrError.  It returns
// err.Err.
func (err *AddrError) Unwrap() (unwrapped error) {
	return err.Err
}

// makeAddrError is a deferrable helper for functions that return [*AddrError].
// errPtr must be non-nil.  Usage example:
//
//	defer makeAddrError(&err, addr, AddrKindARPA)
func makeAddrError(errPtr *error, addr string, k AddrKind) {
	err := *errPtr
	if err == nil {
		return
	}

	*errPtr = &AddrError{
		Err:  err,
		Kind: k,
		Addr: addr,
	}
}

// LabelKind is a convenient alias for string describing the kind of label of a
// name and used for error reporting.
type LabelKind = string

// Kinds of labels for [LabelError].
const (
	LabelKindDomain LabelKind = "domain name label"
	LabelKindHost   LabelKind = "hostname label"
	LabelKindSRV    LabelKind = "service name label"
	LabelKindTLD    LabelKind = "top-level domain name label"
)

// LabelError is the underlying type of errors returned from validation
// functions when a label of a name is invalid.
type LabelError struct {
	// Err is the underlying error, if any.
	Err error

	// Kind is the kind of label of the name.
	Kind LabelKind

	// Label is the text of the invalid label.
	Label string
}

// type check
var _ error = (*AddrError)(nil)

// Error implements the error interface for *AddrError.
func (err *LabelError) Error() (msg string) {
	if err.Err != nil {
		return fmt.Sprintf("bad %s %q: %s", err.Kind, err.Label, err.Err)
	}

	return fmt.Sprintf("bad %s %q", err.Kind, err.Label)
}

// type check
var _ errors.Wrapper = (*AddrError)(nil)

// Unwrap implements the [errors.Wrapper] interface for *AddrError.  It returns
// err.Err.
func (err *LabelError) Unwrap() (unwrapped error) {
	return err.Err
}

// makeLabelError is a deferrable helper for functions that return
// [*LabelError].  errPtr must be non-nil.  Usage example:
//
//	defer makeLabelError(&err, label, LabelKindDomain)
func makeLabelError(errPtr *error, label string, k LabelKind) {
	err := *errPtr
	if err == nil {
		return
	}

	*errPtr = &LabelError{
		Err:   err,
		Kind:  k,
		Label: label,
	}
}

// LengthError is the underlying type of errors returned from validation
// functions when an address or a part of an address has a bad length.  Kind is
// either [AddrKind] or [LabelKind].
type LengthError struct {
	// Kind is the kind of address or address part.
	Kind string

	// Allowed are the allowed lengths for this kind of address.  If allowed
	// is empty, Max should be non-zero.
	Allowed []int

	// Max is the maximum length for this part or address kind.  If Max is
	// zero, Allowed should be non-empty.
	Max int

	// Length is the length of the provided address.
	Length int
}

// Error implements the error interface for *LengthError.
func (err *LengthError) Error() (msg string) {
	if err.Max > 0 {
		return fmt.Sprintf("%s is too long: got %d, max %d", err.Kind, err.Length, err.Max)
	}

	if err.Length == 0 {
		return fmt.Sprintf("%s is empty", err.Kind)
	}

	format := "bad %s length %d, allowed: %v"
	if len(err.Allowed) == 1 {
		return fmt.Sprintf(format, err.Kind, err.Length, err.Allowed[0])
	}

	return fmt.Sprintf(format, err.Kind, err.Length, err.Allowed)
}

// RuneError is the underlying type of errors returned from validation functions
// when a rune in the address is invalid.  Kind is either [AddrKind] or
// [LabelKind].
type RuneError struct {
	// Kind is the kind of address or address part.
	Kind string

	// Rune is the invalid rune.
	Rune rune
}

// Error implements the error interface for *RuneError.
func (err *RuneError) Error() (msg string) {
	return fmt.Sprintf("bad %s rune %q", err.Kind, err.Rune)
}

// replaceKind replaces the Kind field of err with newKind.  err must be of type
// [*LabelError], [*AddrError], [*LengthError], or [*RuneError].
func replaceKind(err error, newKind string) {
	switch err := err.(type) {
	case *LabelError:
		err.Kind = newKind
	case *AddrError:
		err.Kind = newKind
	case *LengthError:
		err.Kind = newKind
	case *RuneError:
		err.Kind = newKind
	default:
		panic(fmt.Errorf("unexpected error type %T", err))
	}
}
