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

package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var consProdText = `The quick brown fox jumped over the lazy dog.`

func TestTextConsumer(t *testing.T) {
	cons := TextConsumer()

	// can consume as a string
	var str string
	err1 := cons.Consume(bytes.NewBuffer([]byte(consProdText)), &str)
	assert.NoError(t, err1)
	assert.Equal(t, consProdText, str)

	var tu textUnmarshalDummy

	// can consume as a TextUnmarshaler
	err3 := cons.Consume(bytes.NewBuffer([]byte(consProdText)), &tu)
	assert.NoError(t, err3)
	assert.Equal(t, consProdText, tu.str)

	// text unmarshal objects can return an error as well, this will be propagated
	assert.Error(t, cons.Consume(bytes.NewBuffer(nil), &tu))

	// when readers can't be read, those errors will be propogated as well
	assert.Error(t, cons.Consume(new(nopReader), &tu))

	// readers can also not be nil
	assert.Error(t, cons.Consume(nil, &tu))

	// can't consume nil ptr's or unsupported types
	assert.Error(t, cons.Consume(bytes.NewBuffer([]byte(consProdText)), nil))
	assert.Error(t, cons.Consume(bytes.NewBuffer([]byte(consProdText)), 42))
	assert.Error(t, cons.Consume(bytes.NewBuffer([]byte(consProdText)), &struct{}{}))
}

type textUnmarshalDummy struct {
	str string
}

func (t *textUnmarshalDummy) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		return errors.New("no text given")
	}

	t.str = string(b)
	return nil
}

type nopReader struct{}

func (n *nopReader) Read(p []byte) (int, error) {
	return 0, errors.New("nop")
}

func TestTextProducer(t *testing.T) {
	prod := TextProducer()
	rw := httptest.NewRecorder()
	err := prod.Produce(rw, consProdText)
	assert.NoError(t, err)
	assert.Equal(t, consProdText, rw.Body.String())
	rw2 := httptest.NewRecorder()
	err2 := prod.Produce(rw2, &consProdText)
	assert.NoError(t, err2)
	assert.Equal(t, consProdText, rw2.Body.String())

	// should always work with type aliases
	// as an alias is sometimes given by generated go-swagger code
	type alias string
	aliasProdText := alias(consProdText)
	rw3 := httptest.NewRecorder()
	err3 := prod.Produce(rw3, aliasProdText)
	assert.NoError(t, err3)
	assert.Equal(t, consProdText, rw3.Body.String())
	rw4 := httptest.NewRecorder()
	err4 := prod.Produce(rw4, &aliasProdText)
	assert.NoError(t, err4)
	assert.Equal(t, consProdText, rw4.Body.String())

	const answer = "42"

	// Should always work with objects implementing Stringer interface
	rw5 := httptest.NewRecorder()
	err5 := prod.Produce(rw5, &stringerDummy{answer})
	assert.NoError(t, err5)
	assert.Equal(t, answer, rw5.Body.String())

	// Should always work with objects implementing TextMarshaler interface
	rw6 := httptest.NewRecorder()
	err6 := prod.Produce(rw6, &textMarshalDummy{answer})
	assert.NoError(t, err6)
	assert.Equal(t, answer, rw6.Body.String())

	rw10 := httptest.NewRecorder()
	err10 := prod.Produce(rw10, errors.New(answer))
	assert.NoError(t, err10)
	assert.Equal(t, answer, rw10.Body.String())

	rw11 := httptest.NewRecorder()
	err11 := prod.Produce(rw11, Error{Message: answer})
	assert.NoError(t, err11)
	assert.Equal(t, fmt.Sprintf(`{"message":%q}`, answer), rw11.Body.String())

	rw12 := httptest.NewRecorder()
	err12 := prod.Produce(rw12, &Error{Message: answer})
	assert.NoError(t, err12)
	assert.Equal(t, fmt.Sprintf(`{"message":%q}`, answer), rw12.Body.String())

	rw13 := httptest.NewRecorder()
	err13 := prod.Produce(rw13, []string{answer})
	assert.NoError(t, err13)
	assert.Equal(t, fmt.Sprintf(`[%q]`, answer), rw13.Body.String())

	// should not work with anything that's not (indirectly) a string
	rw7 := httptest.NewRecorder()
	err7 := prod.Produce(rw7, 42)
	assert.Error(t, err7)
	// nil values should also be safely caught with an error
	rw8 := httptest.NewRecorder()
	err8 := prod.Produce(rw8, nil)
	assert.Error(t, err8)

	// writer can not be nil
	assert.Error(t, prod.Produce(nil, &textMarshalDummy{answer}))

	// should not work for a textMarshaler that returns an error during marshalling
	rw9 := httptest.NewRecorder()
	err9 := prod.Produce(rw9, new(textMarshalDummy))
	assert.Error(t, err9)
}

type Error struct {
	Message string `json:"message"`
}

type stringerDummy struct {
	str string
}

func (t *stringerDummy) String() string {
	return t.str
}

type textMarshalDummy struct {
	str string
}

func (t *textMarshalDummy) MarshalText() ([]byte, error) {
	if t.str == "" {
		return nil, errors.New("no text set")
	}
	return []byte(t.str), nil
}
