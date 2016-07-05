package xfer

import (
	"fmt"
	"net/rpc"
	"sync"
)

// ErrInvalidMessage is the error returned when the on-wire message is unexpected.
var ErrInvalidMessage = fmt.Errorf("Invalid Message")

// Request is the UI -> App -> Probe message type for control RPCs
type Request struct {
	AppID   string // filled in by the probe on receiving this request
	NodeID  string
	Control string
}

// Response is the Probe -> App -> UI message type for the control RPCs.
type Response struct {
	Value interface{} `json:"value,omitempty"`
	Error string      `json:"error,omitempty"`

	// Pipe specific fields
	Pipe   string `json:"pipe,omitempty"`
	RawTTY bool   `json:"raw_tty,omitempty"`

	// Remove specific fields
	RemovedNode string `json:"removedNode,omitempty"` // Set if node was removed
}

// Message is the unions of Request, Response and arbitrary Value.
type Message struct {
	Request  *rpc.Request
	Response *rpc.Response
	Value    interface{}
}

// ControlHandler is interface used in the app and the probe to represent
// a control RPC.
type ControlHandler interface {
	Handle(req Request, res *Response) error
}

// ControlHandlerFunc is a adapter (ala golang's http RequestHandlerFunc)
// for ControlHandler
type ControlHandlerFunc func(Request) Response

// Handle is an adapter method to make ControlHandlers exposable via golang rpc
func (c ControlHandlerFunc) Handle(req Request, res *Response) error {
	*res = c(req)
	return nil
}

// ResponseErrorf creates a new Response with the given formatted error string.
func ResponseErrorf(format string, a ...interface{}) Response {
	return Response{
		Error: fmt.Sprintf(format, a...),
	}
}

// ResponseError creates a new Response with the given error.
func ResponseError(err error) Response {
	if err != nil {
		return Response{
			Error: err.Error(),
		}
	}
	return Response{}
}

// JSONWebsocketCodec is golang rpc compatible Server and Client Codec
// that transmits and receives RPC messages over a websocker, as JSON.
type JSONWebsocketCodec struct {
	sync.Mutex
	conn Websocket
	err  chan error
}

// NewJSONWebsocketCodec makes a new JSONWebsocketCodec
func NewJSONWebsocketCodec(conn Websocket) *JSONWebsocketCodec {
	return &JSONWebsocketCodec{
		conn: conn,
		err:  make(chan error, 1),
	}
}

// WaitForReadError blocks until any read on this codec returns an error.
// This is useful to know when the server has disconnected from the client.
func (j *JSONWebsocketCodec) WaitForReadError() error {
	return <-j.err
}

// WriteRequest implements rpc.ClientCodec
func (j *JSONWebsocketCodec) WriteRequest(r *rpc.Request, v interface{}) error {
	j.Lock()
	defer j.Unlock()

	if err := j.conn.WriteJSON(Message{Request: r}); err != nil {
		return err
	}
	return j.conn.WriteJSON(Message{Value: v})
}

// WriteResponse implements rpc.ServerCodec
func (j *JSONWebsocketCodec) WriteResponse(r *rpc.Response, v interface{}) error {
	j.Lock()
	defer j.Unlock()

	if err := j.conn.WriteJSON(Message{Response: r}); err != nil {
		return err
	}
	return j.conn.WriteJSON(Message{Value: v})
}

func (j *JSONWebsocketCodec) readMessage(v interface{}) (*Message, error) {
	m := Message{Value: v}
	if err := j.conn.ReadJSON(&m); err != nil {
		j.err <- err
		close(j.err)
		return nil, err
	}
	return &m, nil
}

// ReadResponseHeader implements rpc.ClientCodec
func (j *JSONWebsocketCodec) ReadResponseHeader(r *rpc.Response) error {
	m, err := j.readMessage(nil)
	if err != nil {
		return err
	}
	if m.Response == nil {
		return ErrInvalidMessage
	}
	*r = *m.Response
	return nil
}

// ReadResponseBody implements rpc.ClientCodec
func (j *JSONWebsocketCodec) ReadResponseBody(v interface{}) error {
	_, err := j.readMessage(v)
	if err != nil {
		return err
	}
	if v == nil {
		return ErrInvalidMessage
	}
	return nil
}

// Close implements rpc.ClientCodec and rpc.ServerCodec
func (j *JSONWebsocketCodec) Close() error {
	return j.conn.Close()
}

// ReadRequestHeader implements rpc.ServerCodec
func (j *JSONWebsocketCodec) ReadRequestHeader(r *rpc.Request) error {
	m, err := j.readMessage(nil)
	if err != nil {
		return err
	}
	if m.Request == nil {
		return ErrInvalidMessage
	}
	*r = *m.Request
	return nil
}

// ReadRequestBody implements rpc.ServerCodec
func (j *JSONWebsocketCodec) ReadRequestBody(v interface{}) error {
	_, err := j.readMessage(v)
	if err != nil {
		return err
	}
	if v == nil {
		return ErrInvalidMessage
	}
	return nil
}
