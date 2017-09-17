package logrus_fluent

import (
	"errors"
	"fmt"
	"testing"
)

func TestFilterError(t *testing.T) {

	tests := []struct {
		data    interface{}
		isError bool
	}{
		{errors.New("error message"), true},
		{fmt.Errorf("error message"), true},
		{&myError{}, true},
		{1, false},
		{1.0, false},
		{"string value", false},
	}

	for _, tt := range tests {
		target := fmt.Sprintf("%#v", tt)
		result := FilterError(tt.data)
		switch {
		case tt.isError:
			err := tt.data.(error)
			if result != err.Error() {
				t.Errorf("result should be error message: %s", target)
			}
		default:
			if result != tt.data {
				t.Errorf("result should be same as the original data: %s", target)
			}
		}
	}
}

type myError struct{}

func (myError) Error() string { return "myError's Error" }
