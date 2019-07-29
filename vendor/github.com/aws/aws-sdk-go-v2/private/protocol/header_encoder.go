package protocol

import (
	"fmt"
	"net/http"
	"strings"
)

// HeaderMapEncoder builds a map valu
type HeaderMapEncoder struct {
	Prefix string
	Header http.Header
	Err    error
}

// MapSetValue adds a single value to the header.
func (e *HeaderMapEncoder) MapSetValue(k string, v ValueMarshaler) {
	if e.Err != nil {
		return
	}

	str, err := v.MarshalValue()
	if err != nil {
		e.Err = err
		return
	}

	k = strings.TrimSpace(k)
	str = strings.TrimSpace(str)

	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	e.Header.Set(k, str)
}

// List executes the passed in callback with a list encoder based on
// the context of this HeaderMapEncoder.
func (e *HeaderMapEncoder) List(k string) ListEncoder {
	if e.Err != nil {
		return nil
	}

	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	return &HeaderListEncoder{Key: k, Header: e.Header}
}

// Map sets the header element with nested maps appending the
// passed in k to the prefix if one was set.
func (e *HeaderMapEncoder) Map(k string) MapEncoder {
	if e.Err != nil {
		return nil
	}

	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	return &HeaderMapEncoder{Prefix: k, Header: e.Header}
}

// Start does nothing for header encodings.
func (e *HeaderMapEncoder) Start() {}

// End does nothing for header encodings.
func (e *HeaderMapEncoder) End() {}

// MapSetFields Is not implemented, query map of FieldMarshaler is undefined.
func (e *HeaderMapEncoder) MapSetFields(k string, m FieldMarshaler) {
	e.Err = fmt.Errorf("header map encoder MapSetFields not supported, %s", k)
}

// HeaderListEncoder will encode list values nested into a header key.
type HeaderListEncoder struct {
	Key    string
	Header http.Header
	Err    error
}

// ListAddValue encodes an individual list value into the header.
func (e *HeaderListEncoder) ListAddValue(v ValueMarshaler) {
	if e.Err != nil {
		return
	}

	str, err := v.MarshalValue()
	if err != nil {
		e.Err = err
		return
	}

	e.Header.Add(e.Key, str)
}

// List Is not implemented, header list of list is undefined.
func (e *HeaderListEncoder) List() ListEncoder {
	e.Err = fmt.Errorf("header list encoder ListAddList not supported, %s", e.Key)
	return nil
}

// Map Is not implemented, header list of map is undefined.
func (e *HeaderListEncoder) Map() MapEncoder {
	e.Err = fmt.Errorf("header list encoder ListAddMap not supported, %s", e.Key)
	return nil
}

// Start does nothing for header list encodings.
func (e *HeaderListEncoder) Start() {}

// End does nothing for header list encodings.
func (e *HeaderListEncoder) End() {}

// ListAddFields Is not implemented, query list of FieldMarshaler is undefined.
func (e *HeaderListEncoder) ListAddFields(m FieldMarshaler) {
	e.Err = fmt.Errorf("header list encoder ListAddFields not supported, %s", e.Key)
}
