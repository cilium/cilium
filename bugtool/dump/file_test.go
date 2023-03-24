// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFile(t *testing.T) {
	assert := assert.New(t)
	d := t.TempDir()
	fp := path.Join(d, "sub0")
	assert.NoError(os.MkdirAll(fp, 0700))
	objFp := path.Join(fp, "test.o")
	_, err := os.Create(objFp)
	assert.NoError(err)
	fp = path.Join(fp, "test.txt")
	fd, err := os.Create(fp)
	assert.NoError(err)
	_, err = fd.Write([]byte("."))
	assert.NoError(err)
	fd.Close()
	run := ""
	sfn := func(n string, fn func(context.Context) error) error {
		run = n
		return fn(context.Background())
	}
	f := NewFile(d)
	f = f.WithExclude("001/sub[0-9]/*.o")
	dir := t.TempDir()
	c := NewContext(dir, sfn)
	f.Run(context.Background(), c)
	assert.Contains(run, "File:")
	assert.FileExists(path.Join(dir, "001/sub0/test.txt"))
	assert.NoFileExists(path.Join(dir, "001/sub0/test.o"))
}
