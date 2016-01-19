package types

type ServerError struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}
