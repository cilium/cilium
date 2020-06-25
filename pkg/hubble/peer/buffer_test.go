// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package peer

import (
	"errors"
	"fmt"
	"io"
	"testing"

	peerpb "github.com/cilium/cilium/api/v1/peer"

	"github.com/stretchr/testify/assert"
)

func TestBufferPush(t *testing.T) {
	max := 8
	buf := newBuffer(max)
	assert.NotNil(t, buf)
	assert.Equal(t, 0, buf.Len())
	assert.Equal(t, 0, buf.Cap())
	for i := 0; i < max; i++ {
		assert.NoError(t, buf.Push(&peerpb.ChangeNotification{}))
		assert.Equal(t, i+1, buf.Len())
	}
	err := buf.Push(&peerpb.ChangeNotification{})
	assert.Equal(t, fmt.Errorf("max buffer size=%d reached", max), err)
	assert.Equal(t, max, buf.Len())

	buf.Close()
	err = buf.Push(&peerpb.ChangeNotification{})
	assert.Equal(t, errors.New("buffer closed"), err)
	assert.Equal(t, 0, buf.Len())

}

func TestBufferPop(t *testing.T) {
	max := 8
	buf := newBuffer(max)
	assert.NotNil(t, buf)
	assert.Equal(t, 0, buf.Len())
	assert.Equal(t, 0, buf.Cap())
	for i := 0; i < max; i++ {
		assert.NoError(t, buf.Push(&peerpb.ChangeNotification{Name: fmt.Sprintf("#%d", i)}))
		assert.Equal(t, i+1, buf.Len())
	}
	for i := 0; i < max; i++ {
		cn, err := buf.Pop()
		assert.NoError(t, err)
		assert.Equal(t, &peerpb.ChangeNotification{Name: fmt.Sprintf("#%d", i)}, cn)
	}

	// pop should block until a CN is pushed
	done := make(chan struct{})
	go func() {
		assert.NoError(t, buf.Push(&peerpb.ChangeNotification{Name: "test"}))
		done <- struct{}{}
	}()
	cn, err := buf.Pop()
	<-done
	assert.NoError(t, err)
	assert.Equal(t, &peerpb.ChangeNotification{Name: "test"}, cn)

	// pop should block until `Close` is called
	go func() {
		buf.Close()
		done <- struct{}{}
	}()
	cn, err = buf.Pop()
	<-done
	assert.Nil(t, cn)
	assert.Equal(t, io.EOF, err)

	// the buffer's underlying memory should be freed
	assert.Equal(t, 0, buf.Len())
	assert.Equal(t, 0, buf.Cap())
}

func TestBufferPopWithClosedStopChan(t *testing.T) {
	max := 8
	buf := newBuffer(max)
	assert.NotNil(t, buf)
	assert.Equal(t, 0, buf.Len())
	assert.Equal(t, 0, buf.Cap())

	for i := 0; i < max; i++ {
		assert.NoError(t, buf.Push(&peerpb.ChangeNotification{}))
		assert.Equal(t, i+1, buf.Len())
	}
	close(buf.stop)
	cn, err := buf.Pop()
	assert.Nil(t, cn)
	assert.Equal(t, io.EOF, err)
}
