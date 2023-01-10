// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import "fmt"

// NewSSHMetaError returns a new SSHMetaError with the given string and a
// callback function
func NewSSHMetaError(errorString string, callback func() string) *SSHMetaError {
	if callback == nil {
		callback = func() string { return "Invalid callback" }
	}
	return &SSHMetaError{
		errorString:   errorString,
		errorCallBack: callback,
	}
}

// SSHMetaError is a custom error that executes a callback function when its
// Error() function is invoked
type SSHMetaError struct {
	errorString   string
	errorCallBack func() string
}

func (e *SSHMetaError) String() string {
	return fmt.Sprintf(
		"Error: %s\nExtended info: %s\n",
		e.errorString, e.errorCallBack())
}

func (e *SSHMetaError) Error() string {
	return e.String()
}
