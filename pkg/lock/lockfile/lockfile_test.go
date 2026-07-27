// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// this only runs on linux, since that supports per-file-descriptor posix advisory locking
//go:build linux

package lockfile

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lockfile")

	// Test lockfile creation
	lf, err := NewLockfile(path)
	assert.NoError(t, err)
	assert.FileExists(t, path)
	defer lf.Close()

	err = lf.Lock(context.Background(), true)
	assert.NoError(t, err)

	err = lf.Unlock()
	assert.NoError(t, err)
}

func TestLockfileShared(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lockfile")

	// Now, ensure that shared locks work: take two shared locks
	shared1, err := NewLockfile(path)
	assert.NoError(t, err)
	assert.NoError(t, shared1.Lock(context.Background(), false))
	defer shared1.Close()

	shared2, err := NewLockfile(path)
	assert.NoError(t, err)
	assert.NoError(t, shared2.TryLock(false))
	defer shared2.Close()

	// Try and take an exclusive lock; it will fail
	exclusive, err := NewLockfile(path)
	assert.NoError(t, err)
	assert.Error(t, exclusive.TryLock(true))
	defer exclusive.Close()

	// Now, unlock
	assert.NoError(t, shared1.Unlock())
	assert.NoError(t, shared2.Unlock())

	// Take an exclusive lock
	assert.NoError(t, exclusive.TryLock(true))

	// Ensure we can't take a shared lock with an exclusive one
	assert.Error(t, shared1.TryLock(false))
}

func TestLockfileCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lockfile")

	// take an exclusive lock
	exclusive, err := NewLockfile(path)
	assert.NoError(t, err)
	defer exclusive.Close()
	assert.NoError(t, exclusive.Lock(context.Background(), true))

	// try and take another, but it will time out
	fail, err := NewLockfile(path)
	assert.NoError(t, err)
	defer fail.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = fail.Lock(ctx, true) // this will fail
	assert.ErrorContains(t, err, "deadline")

	exclusive.Unlock()
}
