// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jsonutils

import (
	"bytes"
	"encoding/json"

	"github.com/mailru/easyjson"
	"github.com/mailru/easyjson/jlexer"
	"github.com/mailru/easyjson/jwriter"
)

type ejMarshaler = easyjson.Marshaler
type ejUnmarshaler = easyjson.Unmarshaler

// WriteJSON marshals a data structure as JSON.
//
// The difference with [json.Marshal] is that it may check among several alternatives
// to do so.
//
// Currently this allows types that are [easyjson.Marshaler]s to use that route to produce JSON.
func WriteJSON(value interface{}) ([]byte, error) {
	if d, ok := value.(ejMarshaler); ok {
		jw := new(jwriter.Writer)
		d.MarshalEasyJSON(jw)
		return jw.BuildBytes()
	}
	if d, ok := value.(json.Marshaler); ok {
		return d.MarshalJSON()
	}
	return json.Marshal(value)
}

// ReadJSON unmarshals JSON data into a data structure.
//
// The difference with [json.Unmarshal] is that it may check among several alternatives
// to do so.
//
// Currently this allows types that are [easyjson.Unmarshaler]s to use that route to process JSON.
func ReadJSON(data []byte, value interface{}) error {
	trimmedData := bytes.Trim(data, "\x00")
	if d, ok := value.(ejUnmarshaler); ok {
		jl := &jlexer.Lexer{Data: trimmedData}
		d.UnmarshalEasyJSON(jl)
		return jl.Error()
	}

	if d, ok := value.(json.Unmarshaler); ok {
		return d.UnmarshalJSON(trimmedData)
	}

	return json.Unmarshal(trimmedData, value)
}

// FromDynamicJSON turns a go value into a properly JSON typed structure.
//
// "Dynamic JSON" refers to what you get when unmarshaling JSON into an untyped interface{},
// i.e. objects are represented by map[string]interface{}, arrays by []interface{}, and
// all numbers are represented as float64.
func FromDynamicJSON(source, target interface{}) error {
	b, err := WriteJSON(source)
	if err != nil {
		return err
	}

	return ReadJSON(b, target)
}
