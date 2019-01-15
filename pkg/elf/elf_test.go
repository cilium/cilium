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
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type ELFTestSuite struct{}

var (
	_ = Suite(&ELFTestSuite{})

	elfObjCopy = "elf-demo-copy.o"
)

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

var errDifferentFiles = fmt.Errorf("File hashes differ")

func compareFiles(path1, path2 string) error {
	h1, err := hash(path1)
	if err != nil {
		return err
	}
	h2, err := hash(path2)
	if err != nil {
		return err
	}

	if len(h1) != len(h2) {
		return fmt.Errorf("File hashes differ in length")
	}

	for i := range h1 {
		if h1[i] != h2[i] {
			return errDifferentFiles
		}
	}

	return nil
}

func getDemoPath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("Failed to get working directory: %s", err)
	}

	return filepath.Join(wd, "..", "..", "test", "bpf", "elf-demo.o"), nil
}

func (s *ELFTestSuite) TestWrite(c *C) {
	tmpDir, err := ioutil.TempDir("", "cilium_")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tmpDir)

	// Open the elf demo compiled from `test/bpf/elf-demo.c`.
	baseObject, err := getDemoPath()
	c.Assert(err, IsNil)
	elf, err := Open(baseObject)
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
		err = compareFiles(baseObject, objectCopy)
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

	baseObject, err := getDemoPath()
	if err != nil {
		b.Fatal(err)
	}

	elf, err := Open(baseObject)
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
