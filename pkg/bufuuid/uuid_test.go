// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bufuuid

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

type mockReader struct{ current byte }

func (mr *mockReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = mr.current
		mr.current++
	}

	return len(p), nil
}

func TestUUIDGenerator(t *testing.T) {
	for _, slots := range []uint64{1, 8, 64} {
		t.Run(fmt.Sprintf("%d slots", slots), func(t *testing.T) {
			uuider := newWith(&mockReader{}, slots)

			var (
				reader   mockReader
				expected uuid.UUID
				found    uuid.UUID
			)

			for range 128 {
				expected = uuid.Must(uuid.NewRandomFromReader(&reader))
				found = uuider.New()
				assert.Equal(t, expected, found)
			}

			for range 128 {
				expected = uuid.Must(uuid.NewRandomFromReader(&reader))
				uuider.NewInto(&found)
				assert.Equal(t, expected, found)
			}
		})
	}
}

func BenchmarkUUIDGenerator(b *testing.B) {
	for _, slots := range []uint64{1, 2, 4, 8, 16, 32, 64, 128, 256} {
		b.Run(fmt.Sprintf("%d slots", slots), func(b *testing.B) {
			var target uuid.UUID
			uuider := newWith(rand.Reader, slots)
			for range b.N {
				uuider.NewInto(&target)
			}
		})
	}
}
