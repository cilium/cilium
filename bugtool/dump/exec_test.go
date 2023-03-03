// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExec(t *testing.T) {
	assert := assert.New(t)
	e := NewExec("do-cmd", "txt", "echo", "hi")
	run := ""
	sfn := func(n string, fn func(context.Context) error) error {
		run = n
		return fn(context.Background())
	}
	dir := t.TempDir()
	c := NewContext(dir, sfn, 0)
	e.Run(context.Background(), c)
	assert.Equal("Exec:do-cmd", run)
}
