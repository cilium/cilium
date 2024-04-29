// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package elf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.IntegrationTest(tb)
}

var baseObjPath = filepath.Join("..", "..", "test", "bpf", "elf-demo.o")

const elfObjCopy = "elf-demo-copy.o"

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

func TestWrite(t *testing.T) {
	setup(t)

	tmpDir, err := os.MkdirTemp("", "cilium_")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	elf, err := Open(baseObjPath)
	require.NoError(t, err)
	defer elf.Close()

	type testOption struct {
		description  string
		key          string
		kind         symbolKind
		intValue     uint64
		strValue     string
		wantErr      bool
		elfChangeErr error
	}
	testOptions := []testOption{
		{
			description: "test direct copy",
			wantErr:     false,
		},
		{
			description:  "test constant substitution 1",
			key:          "FOO",
			kind:         symbolData,
			intValue:     42,
			wantErr:      false,
			elfChangeErr: errDifferentFiles,
		},
		{
			description:  "test constant substitution 2",
			key:          "BAR",
			kind:         symbolData,
			intValue:     42,
			wantErr:      false,
			elfChangeErr: errDifferentFiles,
		},
		{
			description:  "test map name substitution name",
			key:          "test_cilium_calls_4278124286",
			kind:         symbolString,
			strValue:     "test_cilium_calls_0000000042",
			wantErr:      false,
			elfChangeErr: errDifferentFiles,
		},
		{
			description: "test invalid map name substitution",
			key:         "test_cilium_calls_4278124286",
			kind:        symbolString,
			strValue:    "test_cilium_calls_00",
			wantErr:     true,
		},
	}

	for i := 1; i <= 2; i++ {
		testOptions = append(testOptions, testOption{
			description:  fmt.Sprintf("test ipv6 substitution %d", i),
			key:          fmt.Sprintf("GLOBAL_IPV6_%d", i),
			kind:         symbolData,
			intValue:     42,
			wantErr:      false,
			elfChangeErr: errDifferentFiles,
		})
	}

	for i := 1; i <= 2; i++ {
		testOptions = append(testOptions, testOption{
			description:  fmt.Sprintf("test mac substitution %d", i),
			key:          fmt.Sprintf("LOCAL_MAC_%d", i),
			kind:         symbolData,
			intValue:     42,
			wantErr:      false,
			elfChangeErr: errDifferentFiles,
		})
	}

	for i, test := range testOptions {
		t.Logf("%s", test.description)

		// Create the copy of the ELF with an optional substitution
		intOptions := make(map[string]uint64)
		strOptions := make(map[string]string)
		switch test.kind {
		case symbolData:
			intOptions[test.key] = test.intValue
		case symbolString:
			strOptions[test.key] = test.strValue
		}
		objectCopy := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", i, elfObjCopy))
		err = elf.Write(objectCopy, intOptions, strOptions)
		require.True(t, test.wantErr == (err != nil), "unexpected error: %v", err)
		if test.wantErr {
			continue
		}

		// Ensure the ELF can be parsed by the loader.
		_, err := ebpf.LoadCollectionSpec(objectCopy)
		require.NoError(t, err)

		err = compareFiles(baseObjPath, objectCopy)
		require.Equal(t, test.elfChangeErr, err)

		// Test that the written ELF matches expectations
		modifiedElf, err := Open(objectCopy)
		require.NoError(t, err)
		defer modifiedElf.Close()

		switch test.kind {
		case symbolData:
			value, err := modifiedElf.readOption(test.key)
			require.NoError(t, err)
			require.Equal(t, test.intValue, value)
		case symbolString:
			err := modifiedElf.findString(test.strValue)
			require.NoError(t, err)
		default:
			_, err = modifiedElf.readOption("unknown")
			require.Error(t, err)
		}
		modifiedElf.Close()
	}
}

// BenchmarkWriteELF benchmarks writing a very simple elf demo program.
func BenchmarkWriteELF(b *testing.B) {
	setup(b)

	tmpDir, err := os.MkdirTemp("", "cilium_")
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
		intOptions := make(map[string]uint64)
		strOptions := make(map[string]string)

		objectCopy := filepath.Join(tmpDir, fmt.Sprintf("%d_%s", i, elfObjCopy))
		if err = elf.Write(objectCopy, intOptions, strOptions); err != nil {
			b.Fatal(err)
		}
	}
}

func (elf *ELF) findString(key string) error {
	opt, exists := elf.symbols.strings[key]
	if !exists {
		return fmt.Errorf("no such string %q in ELF", key)
	}
	if _, err := elf.readValue(int64(opt.offset), int64(opt.size)); err != nil {
		return err
	}
	return nil
}

func (elf *ELF) readOption(key string) (result uint64, err error) {
	opt, exists := elf.symbols.data[configPrefix+key]
	if !exists {
		return 0, fmt.Errorf("no such option %q in ELF", key)
	}
	value, err := elf.readValue(int64(opt.offset), int64(opt.size))
	if err != nil {
		return 0, err
	}

	out := make([]byte, 8)
	copy(out, value)
	return elf.metadata.ByteOrder.Uint64(out), err
}

func (elf *ELF) readValue(offset int64, size int64) ([]byte, error) {
	reader := io.NewSectionReader(elf.contents, offset, size)
	result := make([]byte, size)
	if err := binary.Read(reader, elf.metadata.ByteOrder, &result); err != nil {
		return nil, err
	}
	return result, nil
}
