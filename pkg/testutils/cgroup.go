// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

type cache struct {
	once sync.Once
	path string
	err  error
}

var c cache

func cgroup2Path() (string, error) {
	c.once.Do(func() {
		mounts, err := os.ReadFile("/proc/mounts")
		if err != nil {
			c.path, c.err = "", err
			return
		}

		for _, line := range strings.Split(string(mounts), "\n") {
			mount := strings.SplitN(line, " ", 3)
			if mount[0] == "cgroup2" {
				c.path, c.err = mount[1], nil
				return
			}
			continue
		}
		c.path, c.err = "", errors.New("cgroup2 not mounted")
	})

	return c.path, c.err
}

// TempCgroup finds the first cgroup2 mount point on the host and creates a
// temporary cgroup in it. Returns the absolute path to the cgroup.
//
// The cgroup is automatically cleaned up at the end of the test run.
func TempCgroup(tb testing.TB) string {
	tb.Helper()

	cg2, err := cgroup2Path()
	if err != nil {
		tb.Fatal("Can't locate cgroup2 mount:", err)
	}

	cgdir, err := os.MkdirTemp(cg2, "cilium-test")
	if err != nil {
		tb.Fatal("Can't create cgroupv2:", err)
	}

	tb.Cleanup(func() {
		os.Remove(cgdir)
	})

	return cgdir
}
