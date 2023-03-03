// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"path"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDir(t *testing.T) {
	assert := assert.New(t)
	l := &sync.Mutex{}
	run := []string{}
	sfn := func(n string, fn func(context.Context) error) error {
		l.Lock()
		run = append(run, n)
		l.Unlock()
		fn(context.Background())
		return nil
	}
	d := NewDir("dir0", Tasks{
		NewExec("cmd0", "txt", "echo", "0"),
		NewExec("cmd1", "md", "echo", "1"),
		NewDir("dir1", Tasks{
			NewExec("cmd2", "txt", "echo", "2"),
		}),
	})
	dir := t.TempDir()
	c := NewContext(dir, sfn, 0)
	// note: dir0 not included, since it's not evaluated by the scheduler.
	d.Run(context.Background(), c)
	assert.Contains(run, "Exec:cmd0")
	assert.Contains(run, "Exec:cmd1")
	assert.Contains(run, "Exec:cmd2")

	assert.DirExists(path.Join(dir, "dir0"))
	assert.FileExists(path.Join(dir, "dir0/cmd0.txt"))
	assert.FileExists(path.Join(dir, "dir0/cmd1.md"))
	assert.DirExists(path.Join(dir, "dir0/dir1"))
	assert.FileExists(path.Join(dir, "dir0/dir1/cmd2.txt"))
}
