// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

type remoteFile struct {
	bytes []byte

	maxFailures int
	count       int
}

func (r *remoteFile) Read(offset uint64, writer io.Writer) error {
	if int(offset) > len(r.bytes) {
		return io.EOF
	}
	_, err := writer.Write(r.bytes[offset:])
	return err
}

func (r *remoteFile) ReadWithFailure(offset uint64, writer io.Writer) error {
	if int(offset) > len(r.bytes) {
		return io.EOF
	}
	if r.count < r.maxFailures {
		r.count++
		return io.ErrUnexpectedEOF
	}

	_, err := writer.Write(r.bytes[offset:])
	return err

}

func TestCopyWithoutRetry(t *testing.T) {
	remoteFile := &remoteFile{
		bytes: []byte{1, 2, 3},
	}

	pipe := newPipe(&CopyOptions{
		ReadFunc: remoteFile.Read,
	})

	res := &bytes.Buffer{}
	_, err := io.Copy(res, pipe)
	assert.NoError(t, err)
	assert.Equal(t, remoteFile.bytes, res.Bytes())
}

func TestCopyWithRetry(t *testing.T) {
	remoteFile := &remoteFile{
		bytes:       []byte{1, 2, 3},
		maxFailures: 2,
	}

	pipe := newPipe(&CopyOptions{
		ReadFunc: remoteFile.ReadWithFailure,
		MaxTries: 3,
	})

	res := &bytes.Buffer{}
	_, err := io.Copy(res, pipe)
	assert.NoError(t, err)
	assert.Equal(t, remoteFile.bytes, res.Bytes())
}

func TestCopyWithExhaustedRetry(t *testing.T) {
	remoteFile := &remoteFile{
		bytes:       []byte{1, 2, 3},
		maxFailures: 3,
	}

	pipe := newPipe(&CopyOptions{
		ReadFunc: remoteFile.ReadWithFailure,
		MaxTries: 2,
	})

	res := &bytes.Buffer{}
	_, err := io.Copy(res, pipe)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "dropping out copy after 2 retries: unexpected EOF")
	assert.Empty(t, res.Bytes())
}
