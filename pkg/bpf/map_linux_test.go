// Copyright 2018 Authors of Cilium
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

// +build privileged_tests

package bpf

import (
	"fmt"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type BPFPrivilegedTestSuite struct{}

var _ = Suite(&BPFPrivilegedTestSuite{})

var (
	maxEntries = 2

	testMap = NewMap("cilium_test",
		MapTypeHash,
		4,
		4,
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		nil)
)

func runTests(m *testing.M) (int, error) {
	CheckOrMountFS("")

	_, err := testMap.OpenOrCreate()
	if err != nil {
		return 1, fmt.Errorf("Failed to create map")
	}
	defer func() {
		path, _ := testMap.Path()
		os.Remove(path)
	}()
	defer testMap.Close()

	return m.Run(), nil
}

func TestMain(m *testing.M) {
	exitCode, err := runTests(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

func (s *BPFPrivilegedTestSuite) TestGetMapInfo(c *C) {
	mi, err := GetMapInfo(os.Getpid(), testMap.fd)
	c.Assert(err, IsNil)
	c.Assert(&testMap.MapInfo, checker.DeepEquals, mi)
}

func (s *BPFPrivilegedTestSuite) TestOpen(c *C) {
	// Ensure that os.IsNotExist() can be used with Map.Open()
	noSuchMap := NewMap("cilium_test_no_exist",
		MapTypeHash, 4, 4, maxEntries, 0, 0, nil)
	err := noSuchMap.Open()
	c.Assert(os.IsNotExist(err), Equals, true)
	c.Assert(err, ErrorMatches, ".*cilium_test_no_exist.*")

	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		4,
		4,
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		nil)
	err = existingMap.Open()
	c.Check(err, IsNil)      // Avoid assert to ensure Close() is called below.
	err = existingMap.Open() // Reopen should be no-op.
	c.Check(err, IsNil)
	err = existingMap.Close()
	c.Assert(err, IsNil)
}
