package helpers

import "fmt"

// NewSSHMetaError returns a new SSHMetaError with the given string and a
// callback function
func NewSSHMetaError(s string, callback func() string) *SSHMetaError {
	return &SSHMetaError{
		s:       s,
		errorCB: callback,
	}
}

// SSHMetaError is a custom error that executes a callback function each time
// that it's called Error() function
type SSHMetaError struct {
	s       string
	errorCB func() string
}

func (e *SSHMetaError) String() string {
	return fmt.Sprintf(
		"Error: %s\nExtended info: %s\n",
		e.s, e.errorCB())
}

func (e *SSHMetaError) Error() string {
	return e.String()
}
