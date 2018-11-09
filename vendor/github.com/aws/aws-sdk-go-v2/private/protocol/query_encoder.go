package protocol

import (
	"fmt"
	"net/url"
)

// QueryMapEncoder builds a query string.
type QueryMapEncoder struct {
	Prefix string
	Query  url.Values
	Err    error
}

// List will return a new QueryListEncoder.
func (e *QueryMapEncoder) List(k string) ListEncoder {
	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	return &QueryListEncoder{k, e.Query, nil}
}

// Map will return a new QueryMapEncoder.
func (e *QueryMapEncoder) Map(k string) MapEncoder {
	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	return &QueryMapEncoder{k, e.Query, nil}
}

// Start does nothing.
func (e *QueryMapEncoder) Start() {}

// End does nothing.
func (e *QueryMapEncoder) End() {}

// MapSetValue adds a single value to the query.
func (e *QueryMapEncoder) MapSetValue(k string, v ValueMarshaler) {
	if e.Err != nil {
		return
	}

	str, err := v.MarshalValue()
	if err != nil {
		e.Err = err
		return
	}

	if len(e.Prefix) > 0 {
		k = e.Prefix + k
	}

	e.Query.Add(k, str)
}

// MapSetFields Is not implemented, query map of map is undefined.
func (e *QueryMapEncoder) MapSetFields(k string, m FieldMarshaler) {
	e.Err = fmt.Errorf("query map encoder MapSetFields not supported, %s", e.Prefix)
}

// QueryListEncoder will encode list values nested into a query key.
type QueryListEncoder struct {
	Key   string
	Query url.Values
	Err   error
}

// List will return a new QueryListEncoder.
func (e *QueryListEncoder) List() ListEncoder {
	return &QueryListEncoder{e.Key, e.Query, nil}
}

// Start does nothing for the query protocol.
func (e *QueryListEncoder) Start() {}

// End does nothing for the query protocol.
func (e *QueryListEncoder) End() {}

// Map will return a new QueryMapEncoder.
func (e *QueryListEncoder) Map() MapEncoder {
	k := e.Key
	return &QueryMapEncoder{k, e.Query, nil}
}

// ListAddValue encodes an individual list value into the querystring.
func (e *QueryListEncoder) ListAddValue(v ValueMarshaler) {
	if e.Err != nil {
		return
	}

	str, err := v.MarshalValue()
	if err != nil {
		e.Err = err
		return
	}

	e.Query.Add(e.Key, str)
}

// ListAddFields Is not implemented, query list of FieldMarshaler is undefined.
func (e *QueryListEncoder) ListAddFields(m FieldMarshaler) {
	e.Err = fmt.Errorf("query list encoder ListAddFields not supported, %s", e.Key)
}
