package types

import "fmt"

// ServerError is the type of message used when the daemon returns any error messages
// in case of failure.
type ServerError struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// String returns string format of the given ServerError.
func (se ServerError) String() string {
	return fmt.Sprintf("%d: %s", se.Code, se.Text)
}
