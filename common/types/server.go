package types

// ServerError is the type of message used when the daemon returns any error messages
// in case of failure.
type ServerError struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}
