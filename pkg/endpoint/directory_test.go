// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func (s *EndpointSuite) TestMoveNewFilesTo(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	f1, err := os.CreateTemp(oldDir, "")
	require.Nil(t, err)
	f2, err := os.CreateTemp(oldDir, "")
	require.Nil(t, err)
	f3, err := os.CreateTemp(newDir, "")
	require.Nil(t, err)

	// Copy the same file in both directories to make sure the same files
	// are not moved from the old directory into the new directory.
	err = os.WriteFile(filepath.Join(oldDir, "foo"), []byte(""), os.FileMode(0644))
	require.Nil(t, err)
	err = os.WriteFile(filepath.Join(newDir, "foo"), []byte(""), os.FileMode(0644))
	require.Nil(t, err)

	compareDir := func(dir string, wantedFiles []string) {
		files, err := os.ReadDir(dir)
		require.Nil(t, err)
		filesNames := make([]string, 0, len(wantedFiles))
		for _, file := range files {
			filesNames = append(filesNames, file.Name())
		}
		require.EqualValues(t, filesNames, wantedFiles)
	}

	type args struct {
		oldDir string
		newDir string
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantOldDir []string
		wantNewDir []string
	}{
		{
			name: "copying from one directory to the other",
			args: args{
				oldDir: oldDir,
				newDir: newDir,
			},
			wantErr: false,
			wantOldDir: []string{
				"foo",
			},
			wantNewDir: []string{
				f1.Name(),
				f2.Name(),
				f3.Name(),
				"foo",
			},
		},
	}
	for _, tt := range tests {
		if err := copyExistingState(tt.args.oldDir, tt.args.newDir); (err != nil) != tt.wantErr {
			require.Equal(t, tt.wantErr, err != nil)
			compareDir(tt.args.oldDir, tt.wantOldDir)
			compareDir(tt.args.newDir, tt.wantNewDir)
		}
	}
}

func benchmarkMoveNewFilesTo(b *testing.B, numFiles int) {
	oldDir := b.TempDir()
	newDir := b.TempDir()
	numDuplicates := int(math.Round(float64(numFiles) * 0.25))

	for n := 0; n < numFiles; n++ {
		name := fmt.Sprintf("file%d", n)
		if err := os.WriteFile(filepath.Join(oldDir, name), []byte{}, os.FileMode(0644)); err != nil {
			b.Fatal(err)
		}

		if n < numDuplicates {
			if err := os.WriteFile(filepath.Join(newDir, name), []byte{}, os.FileMode(0644)); err != nil {
				b.Fatal(err)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := copyExistingState(oldDir, newDir); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()

	os.RemoveAll(oldDir)
	os.RemoveAll(newDir)
}

func BenchmarkMoveNewFilesTo1(b *testing.B) {
	benchmarkMoveNewFilesTo(b, 1)
}

func BenchmarkMoveNewFilesTo5(b *testing.B) {
	benchmarkMoveNewFilesTo(b, 5)
}

func BenchmarkMoveNewFilesTo10(b *testing.B) {
	benchmarkMoveNewFilesTo(b, 10)
}
