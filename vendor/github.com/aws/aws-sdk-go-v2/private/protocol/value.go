package protocol

import (
	"reflect"
)

// ErrValueNotSet is an error that is returned when the value
// has not been set.
type ErrValueNotSet struct{}

func (err *ErrValueNotSet) Error() string {
	return "value not set"
}

// IsNotSetError will return true if the error is of ErrValueNotSet
func IsNotSetError(err error) bool {
	_, ok := err.(*ErrValueNotSet)
	return ok
}

// GetValue will return the value that is associated with the reflect.Value.
// If that value is not set, this will return an ErrValueNotSet
func GetValue(r reflect.Value) (string, error) {
	val := r.String()
	if len(val) == 0 {
		return "", &ErrValueNotSet{}
	}

	return val, nil
}
