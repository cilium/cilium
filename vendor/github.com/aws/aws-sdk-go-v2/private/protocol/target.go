package protocol

import "fmt"

// Target is the encode and decode targets of protocol marshaling.
type Target int

// The protocol marshaling targets.
const (
	PathTarget Target = iota
	QueryTarget
	HeaderTarget
	HeadersTarget
	StatusCodeTarget
	BodyTarget
	PayloadTarget
)

func (e Target) String() string {
	switch e {
	case PathTarget:
		return "Path"
	case QueryTarget:
		return "Query"
	case HeaderTarget:
		return "Header"
	case HeadersTarget:
		return "Headers"
	case StatusCodeTarget:
		return "StatusCode"
	case BodyTarget:
		return "Body"
	case PayloadTarget:
		return "Payload"
	default:
		panic(fmt.Sprintf("// unknown encoding target, %d", e))
	}
}
