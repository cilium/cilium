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
	"regexp"
	"strings"
	"time"

	"github.com/globalsign/mgo/bson"
	"github.com/mailru/easyjson/jlexer"
	"github.com/mailru/easyjson/jwriter"
)

func init() {
	dt := DateTime{}
	Default.Add("datetime", &dt, IsDateTime)
}

// IsDateTime returns true when the string is a valid date-time
func IsDateTime(str string) bool {
	if len(str) < 4 {
		return false
	}
	s := strings.Split(strings.ToLower(str), "t")
	if len(s) < 2 || !IsDate(s[0]) {
		return false
	}

	matches := rxDateTime.FindAllStringSubmatch(s[1], -1)
	if len(matches) == 0 || len(matches[0]) == 0 {
		return false
	}
	m := matches[0]
	res := m[1] <= "23" && m[2] <= "59" && m[3] <= "59"
	return res
}

const (
	// RFC3339Millis represents a ISO8601 format to millis instead of to nanos
	RFC3339Millis = "2006-01-02T15:04:05.000Z07:00"
	// RFC3339Micro represents a ISO8601 format to micro instead of to nano
	RFC3339Micro = "2006-01-02T15:04:05.000000Z07:00"
	// DateTimePattern pattern to match for the date-time format from http://tools.ietf.org/html/rfc3339#section-5.6
	DateTimePattern = `^([0-9]{2}):([0-9]{2}):([0-9]{2})(.[0-9]+)?(z|([+-][0-9]{2}:[0-9]{2}))$`
)

var (
	dateTimeFormats = []string{RFC3339Micro, RFC3339Millis, time.RFC3339, time.RFC3339Nano}
	rxDateTime      = regexp.MustCompile(DateTimePattern)
	// MarshalFormat sets the time resolution format used for marshaling time (set to milliseconds)
	MarshalFormat = RFC3339Millis
)

// ParseDateTime parses a string that represents an ISO8601 time or a unix epoch
func ParseDateTime(data string) (DateTime, error) {
	if data == "" {
		return NewDateTime(), nil
	}
	var lastError error
	for _, layout := range dateTimeFormats {
		dd, err := time.Parse(layout, data)
		if err != nil {
			lastError = err
			continue
		}
		lastError = nil
		return DateTime(dd), nil
	}
	return DateTime{}, lastError
}

// DateTime is a time but it serializes to ISO8601 format with millis
// It knows how to read 3 different variations of a RFC3339 date time.
// Most APIs we encounter want either millisecond or second precision times.
// This just tries to make it worry-free.
//
// swagger:strfmt date-time
type DateTime time.Time

// NewDateTime is a representation of zero value for DateTime type
func NewDateTime() DateTime {
	return DateTime(time.Unix(0, 0).UTC())
}

// String converts this time to a string
func (t DateTime) String() string {
	return time.Time(t).Format(MarshalFormat)
}

// MarshalText implements the text marshaller interface
func (t DateTime) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements the text unmarshaller interface
func (t *DateTime) UnmarshalText(text []byte) error {
	tt, err := ParseDateTime(string(text))
	if err != nil {
		return err
	}
	*t = tt
	return nil
}

// Scan scans a DateTime value from database driver type.
func (t *DateTime) Scan(raw interface{}) error {
	// TODO: case int64: and case float64: ?
	switch v := raw.(type) {
	case []byte:
		return t.UnmarshalText(v)
	case string:
		return t.UnmarshalText([]byte(v))
	case time.Time:
		*t = DateTime(v)
	case nil:
		*t = DateTime{}
	default:
		return fmt.Errorf("cannot sql.Scan() strfmt.DateTime from: %#v", v)
	}

	return nil
}

// Value converts DateTime to a primitive value ready to written to a database.
func (t DateTime) Value() (driver.Value, error) {
	return driver.Value(t.String()), nil
}

// MarshalJSON returns the DateTime as JSON
func (t DateTime) MarshalJSON() ([]byte, error) {
	var w jwriter.Writer
	t.MarshalEasyJSON(&w)
	return w.BuildBytes()
}

// MarshalEasyJSON writes the DateTime to a easyjson.Writer
func (t DateTime) MarshalEasyJSON(w *jwriter.Writer) {
	w.String(time.Time(t).Format(MarshalFormat))
}

// UnmarshalJSON sets the DateTime from JSON
func (t *DateTime) UnmarshalJSON(data []byte) error {
	l := jlexer.Lexer{Data: data}
	t.UnmarshalEasyJSON(&l)
	return l.Error()
}

// UnmarshalEasyJSON sets the DateTime from a easyjson.Lexer
func (t *DateTime) UnmarshalEasyJSON(in *jlexer.Lexer) {
	if data := in.String(); in.Ok() {
		tt, err := ParseDateTime(data)
		if err != nil {
			in.AddError(err)
			return
		}
		*t = tt
	}
}

// GetBSON returns the DateTime as a bson.M{} map.
func (t *DateTime) GetBSON() (interface{}, error) {
	return bson.M{"data": t.String()}, nil
}

// SetBSON sets the DateTime from raw bson data
func (t *DateTime) SetBSON(raw bson.Raw) error {
	var m bson.M
	if err := raw.Unmarshal(&m); err != nil {
		return err
	}

	if data, ok := m["data"].(string); ok {
		var err error
		*t, err = ParseDateTime(data)
		return err
	}

	return errors.New("couldn't unmarshal bson raw value as Duration")
}

// DeepCopyInto copies the receiver and writes its value into out.
func (t *DateTime) DeepCopyInto(out *DateTime) {
	*out = *t
}

// DeepCopy copies the receiver into a new DateTime.
func (t *DateTime) DeepCopy() *DateTime {
	if t == nil {
		return nil
	}
	out := new(DateTime)
	t.DeepCopyInto(out)
	return out
}
