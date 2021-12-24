package k8s

import (
	"bytes"
	"io"
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type CopyPipeSuites struct{}

var _ = check.Suite(&CopyPipeSuites{})

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

func (b *CopyPipeSuites) TestCopyWithoutRetry(c *check.C) {
	remoteFile := &remoteFile{
		bytes: []byte{1, 2, 3},
	}

	pipe := newPipe(&CopyOptions{
		ReadFunc: remoteFile.Read,
	})

	res := &bytes.Buffer{}
	_, err := io.Copy(res, pipe)
	c.Assert(err, check.IsNil)
	c.Assert(res.Bytes(), check.DeepEquals, remoteFile.bytes)
}

func (b *CopyPipeSuites) TestCopyWithRetry(c *check.C) {
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
	c.Assert(err, check.IsNil)
	c.Assert(res.Bytes(), check.DeepEquals, remoteFile.bytes)
}

func (b *CopyPipeSuites) TestCopyWithExhaustedRetry(c *check.C) {
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
	c.Assert(err, check.NotNil)
	c.Assert(err, check.ErrorMatches, "dropping out copy after 2 retries: unexpected EOF")
	c.Assert(res.Bytes(), check.HasLen, 0)
}
