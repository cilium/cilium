// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package elf

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/testutils"
)

// Hook up gocheck into the "go test" runner.
type ELFTestSuite struct{}

var (
	_ = Suite(&ELFTestSuite{})

	baseObjPath = filepath.Join(testutils.CiliumRootDir, "test", "bpf", "elf-demo.o")
)

const elfObjCopy = "elf-demo-copy.o"

func Test(t *testing.T) {
	TestingT(t)
}

func hash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

var errDifferentFiles = fmt.Errorf("file hashes differ")

func compareFiles(path1, path2 string) error {
	h1, err := hash(path1)
	if err != nil {
		return err
	}
	h2, err := hash(path2)
	if err != nil {
		return err
	}

	if !bytes.Equal(h1, h2) {
		return errDifferentFiles
	}
	return nil
}

func (s *ELFTestSuite) TestWrite(c *C) {
	tmpDir, err := ioutil.TempDir("", "cilium_")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	elf, err := Open(baseObjPath)
	c.Assert(err, IsNil)
	defer elf.Close()

	validOptions := IsNil
	notValidOptions := Not(validOptions)
	type testOption struct {
		description  string
		key          string
		kind         symbolKind
		intValue     uint32
		strValue     string
		elfValid     Checker
		elfChangeErr error
	}
	testOptions := []testOption{
		{
			description: "test direct copy",
			elfValid:    validOptions,
		},
		{
			description:  "test constant substitution 1",
			key:          "FOO",
			kind:         symbolUint32,
			intValue:     42,
			elfValid:     validOptions,
			elfChangeErr: errDifferentFiles,
		},
		{
			description:  "test constant substitution 2",
			key:          "BAR",
			kind:         symbolUint32,
			intValue:     42,
			elfValid:     validOptions,
			elfChangeErr: errDifferentFiles,
		},
		{
			description:  "test map name substitution name",
			key:          "test_cilium_calls_4278124286",
			kind:         symbolString,
			strValue:     "test_cilium_calls_0000000042",
			elfValid:     validOptions,
			elfChangeErr: errDifferentFiles,
		},
		{
			description: "test invalid map name substitution",
			key:         "test_cilium_calls_4278124286",
			kind:        symbolString,
			strValue:    "test_cilium_calls_00",
			elfValid:    notValidOptions,
		},
	}

	for i := 1; i <= 4; i++ {
		testOptions = append(testOptions, testOption{
			description:  fmt.Sprintf("test ipv6 substitution %d", i),
			key:          fmt.Sprintf("GLOBAL_IPV6_%d", i),
			kind:         symbolUint32,
			intValue:     42,
			elfValid:     validOptions,
			elfChangeErr: errDifferentFiles,
		})
	}

	for i := 1; i <= 2; i++ {
		testOptions = append(testOptions, testOption{
			description:  fmt.Sprintf("test mac substitution %d", i),
			key:          fmt.Sprintf("LOCAL_MAC_%d", i),
			kind:         symbolUint32,
			intValue:     42,
			elfValid:     validOptions,
			elfChangeErr: errDifferentFiles,
		})
	}

	for i, test := range testOptions {
		c.Logf("%s", test.description)

		// Create the copy of the ELF with an optional substitution
		intOptions := make(map[string]uint32)
		strOptions := make(map[string]string)
		switch test.kind {
		case symbolUint32:
			intOptions[test.key] = test.intValue
		case symbolString:
			strOptions[test.key] = test.strValue
		}
		objectCopy := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", i, elfObjCopy))
		err = elf.Write(objectCopy, intOptions, strOptions)
		c.Assert(err, test.elfValid)
		if test.elfValid == notValidOptions {
			continue
		}
		err = compareFiles(baseObjPath, objectCopy)
		c.Assert(err, Equals, test.elfChangeErr)

		// Test that the written ELF matches expectations
		modifiedElf, err := Open(objectCopy)
		c.Assert(err, IsNil)
		defer modifiedElf.Close()

		switch test.kind {
		case symbolUint32:
			value, err := modifiedElf.readOption(test.key)
			c.Assert(err, IsNil)
			c.Assert(value, Equals, test.intValue)
		case symbolString:
			err := modifiedElf.findString(test.strValue)
			c.Assert(err, IsNil)
		default:
			_, err = modifiedElf.readOption("unknown")
			c.Assert(err, NotNil)
		}
		modifiedElf.Close()
	}
}

// BenchmarkWriteELF benchmarks writing a very simple elf demo program.
func BenchmarkWriteELF(b *testing.B) {
	tmpDir, err := ioutil.TempDir("", "cilium_")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	elf, err := Open(baseObjPath)
	if err != nil {
		b.Fatal(err)
	}
	defer elf.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		intOptions := make(map[string]uint32)
		strOptions := make(map[string]string)

		objectCopy := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", i, elfObjCopy))
		if err = elf.Write(objectCopy, intOptions, strOptions); err != nil {
			b.Fatal(err)
		}
	}
}
