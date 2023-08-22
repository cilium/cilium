// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactCopier_Copy_SourceDirDoesntExist(t *testing.T) {
	sourceTempDir := "/tmp/not-existing"
	targetTempDir := t.TempDir()

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err := r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Empty(t, files)
}

func TestArtifactCopier_Copy_EmptySourceDir(t *testing.T) {
	sourceTempDir := t.TempDir()
	targetTempDir := t.TempDir()

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err := r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Empty(t, files)
}

func TestArtifactCopier_Copy_CopyFiles(t *testing.T) {
	sourceTempDir := t.TempDir()
	targetTempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(sourceTempDir, "test.txt"), []byte("testcontent"), os.ModePerm)
	assert.NoError(t, err)

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err = r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "test.txt", files[0].Name())

	fileContent, err := os.ReadFile(filepath.Join(targetTempDir, files[0].Name()))
	assert.NoError(t, err)
	assert.Equal(t, "testcontent", string(fileContent))
}

func TestArtifactCopier_Copy_DontCopySymlinks(t *testing.T) {
	sourceTempDir := t.TempDir()
	targetTempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(sourceTempDir, "test.txt"), []byte("testcontent"), os.ModePerm)
	assert.NoError(t, err)

	err = os.Symlink(filepath.Join(sourceTempDir, "test.txt"), filepath.Join(sourceTempDir, "symlink"))
	assert.NoError(t, err)

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err = r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "test.txt", files[0].Name())
}

func TestArtifactCopier_Copy_DontCopyDirectories(t *testing.T) {
	sourceTempDir := t.TempDir()
	targetTempDir := t.TempDir()

	err := os.Mkdir(filepath.Join(sourceTempDir, "sub-directory"), os.ModePerm)
	assert.NoError(t, err)

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err = r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Empty(t, files)
}

func TestArtifactCopier_Copy_CleanupExistingContent(t *testing.T) {
	sourceTempDir := t.TempDir()
	targetTempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(sourceTempDir, "new-file.txt"), []byte("testcontent"), os.ModePerm)
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(targetTempDir, "existing-file.txt"), []byte("testcontent"), os.ModePerm)
	assert.NoError(t, err)

	err = os.Mkdir(filepath.Join(targetTempDir, "sub-directory"), os.ModePerm)
	assert.NoError(t, err)

	r := &ArtifactCopier{
		sourcePath: sourceTempDir,
		targetPath: targetTempDir,
	}

	err = r.Copy()
	assert.NoError(t, err)

	files, err := os.ReadDir(targetTempDir)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "new-file.txt", files[0].Name())

	fileContent, err := os.ReadFile(filepath.Join(targetTempDir, files[0].Name()))
	assert.NoError(t, err)
	assert.Equal(t, "testcontent", string(fileContent))
}
