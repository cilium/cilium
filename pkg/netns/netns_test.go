// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"fmt"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func lock(t *testing.T) {
	restoreUnlock, err := lockOSThread()
	if err != nil {
		t.Fatalf("locking OS thread: %s", err)
	}

	t.Cleanup(func() {
		restoreUnlock()
	})
}

func get(t *testing.T) *NetNS {
	orig, err := getCurrent()
	assert.NoError(t, err)

	return newNetNS(orig)
}

func TestNetNSUnchangedAfterCreate(t *testing.T) {
	testutils.PrivilegedTest(t)
	lock(t)

	orig := get(t)
	defer orig.Close()

	ns, err := New()
	assert.NoError(t, err)
	defer ns.Close()

	after := get(t)
	defer after.Close()

	assert.False(t, equal(ns, orig))
	assert.True(t, equal(orig, after))
}

func TestNetNSSet(t *testing.T) {
	testutils.PrivilegedTest(t)
	lock(t)

	ns, err := New()
	assert.NoError(t, err)
	defer ns.Close()

	orig := get(t)
	defer orig.Close()

	assert.False(t, equal(ns, orig))

	assert.NoError(t, set(ns.f))

	after := get(t)
	defer after.Close()

	assert.True(t, equal(ns, after))
}

func TestNetNSClose(t *testing.T) {
	testutils.PrivilegedTest(t)
	lock(t)

	ns, err := New()
	assert.NoError(t, err)

	assert.NoError(t, ns.Close())

	assert.Nil(t, ns.f)
	assert.Equal(t, ns.FD(), -1)
}

func TestNetNSDo(t *testing.T) {
	testutils.PrivilegedTest(t)
	lock(t)

	origTID := unix.Gettid()
	orig := get(t)
	defer orig.Close()

	ns, err := New()
	assert.NoError(t, err)
	defer ns.Close()

	assert.NoError(t,
		ns.Do(func() error {
			innerTID := unix.Gettid()
			if innerTID == origTID {
				return fmt.Errorf("original TID %d should not match inner TID %d", origTID, innerTID)
			}

			inner := get(t)
			if !equal(inner, ns) {
				return fmt.Errorf("inner netns fd doesn't match fd in ns handle")
			}

			return nil
		}))

	after := get(t)
	defer after.Close()
	assert.True(t, equal(orig, after))
}

func equal(some *NetNS, other *NetNS) bool {
	if some.FD() == other.FD() {
		return true
	}

	// Fall back to checking inodes if fds don't match.
	var s1, s2 unix.Stat_t
	if err := unix.Fstat(int(some.FD()), &s1); err != nil {
		return false
	}
	if err := unix.Fstat(int(other.FD()), &s2); err != nil {
		return false
	}
	return (s1.Dev == s2.Dev) && (s1.Ino == s2.Ino)
}
