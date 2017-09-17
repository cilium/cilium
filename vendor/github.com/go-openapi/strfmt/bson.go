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

package strfmt

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/mailru/easyjson/jlexer"
	"github.com/mailru/easyjson/jwriter"

	"gopkg.in/mgo.v2/bson"
)

func init() {
	var id ObjectId
	Default.Add("bsonobjectid", &id, IsBSONObjectID)
}

// IsBSONObjectID returns true when the string is a valid BSON.ObjectId
func IsBSONObjectID(str string) bool {
	var id bson.ObjectId
	return id.UnmarshalText([]byte(str)) == nil
}

type ObjectId bson.ObjectId

// NewObjectId creates a ObjectId from a Hex String
func NewObjectId(hex string) ObjectId {
	return ObjectId(bson.ObjectIdHex(hex))
}

// MarshalText turns this instance into text
func (id *ObjectId) MarshalText() ([]byte, error) {
	return []byte(bson.ObjectId(*id).Hex()), nil
}

// UnmarshalText hydrates this instance from text
func (id *ObjectId) UnmarshalText(data []byte) error { // validation is performed later on
	var rawID bson.ObjectId
	if err := rawID.UnmarshalText(data); err != nil {
		return err
	}

	*id = ObjectId(rawID)
	return nil
}

// Scan read a value from a database driver
func (id *ObjectId) Scan(raw interface{}) error {
	var data []byte
	switch v := raw.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("cannot sql.Scan() strfmt.URI from: %#v", v)
	}

	return id.UnmarshalText(data)
}

// Value converts a value to a database driver value
func (id *ObjectId) Value() (driver.Value, error) {
	return driver.Value(string(*id)), nil
}

func (id *ObjectId) String() string {
	return string(*id)
}

func (id *ObjectId) MarshalJSON() ([]byte, error) {
	var w jwriter.Writer
	id.MarshalEasyJSON(&w)
	return w.BuildBytes()
}

func (id *ObjectId) MarshalEasyJSON(w *jwriter.Writer) {
	w.String(bson.ObjectId(*id).Hex())
}

func (id *ObjectId) UnmarshalJSON(data []byte) error {
	l := jlexer.Lexer{Data: data}
	id.UnmarshalEasyJSON(&l)
	return l.Error()
}

func (id *ObjectId) UnmarshalEasyJSON(in *jlexer.Lexer) {
	if data := in.String(); in.Ok() {
		*id = NewObjectId(data)
	}
}

func (id *ObjectId) GetBSON() (interface{}, error) {
	return bson.M{"data": bson.ObjectId(*id).Hex()}, nil
}

func (id *ObjectId) SetBSON(raw bson.Raw) error {
	var m bson.M
	if err := raw.Unmarshal(&m); err != nil {
		return err
	}

	if data, ok := m["data"].(string); ok {
		*id = NewObjectId(data)
		return nil
	}

	return errors.New("couldn't unmarshal bson raw value as ObjectId")
}
