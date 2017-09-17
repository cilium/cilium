package archive

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/docker/docker/pkg/system"
)

func max(x, y int) int {
	if x >= y {
		return x
	}
	return y
}

func copyDir(src, dst string) error {
	cmd := exec.Command("cp", "-a", src, dst)
	if runtime.GOOS == "solaris" {
		cmd = exec.Command("gcp", "-a", src, dst)
	}

	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

type FileType uint32

const (
	Regular FileType = iota
	Dir
	Symlink
)

type FileData struct {
	filetype    FileType
	path        string
	contents    string
	permissions os.FileMode
}

func createSampleDir(t *testing.T, root string) {
	files := []FileData{
		{Regular, "file1", "file1\n", 0600},
		{Regular, "file2", "file2\n", 0666},
		{Regular, "file3", "file3\n", 0404},
		{Regular, "file4", "file4\n", 0600},
		{Regular, "file5", "file5\n", 0600},
		{Regular, "file6", "file6\n", 0600},
		{Regular, "file7", "file7\n", 0600},
		{Dir, "dir1", "", 0740},
		{Regular, "dir1/file1-1", "file1-1\n", 01444},
		{Regular, "dir1/file1-2", "file1-2\n", 0666},
		{Dir, "dir2", "", 0700},
		{Regular, "dir2/file2-1", "file2-1\n", 0666},
		{Regular, "dir2/file2-2", "file2-2\n", 0666},
		{Dir, "dir3", "", 0700},
		{Regular, "dir3/file3-1", "file3-1\n", 0666},
		{Regular, "dir3/file3-2", "file3-2\n", 0666},
		{Dir, "dir4", "", 0700},
		{Regular, "dir4/file3-1", "file4-1\n", 0666},
		{Regular, "dir4/file3-2", "file4-2\n", 0666},
		{Symlink, "symlink1", "target1", 0666},
		{Symlink, "symlink2", "target2", 0666},
		{Symlink, "symlink3", root + "/file1", 0666},
		{Symlink, "symlink4", root + "/symlink3", 0666},
		{Symlink, "dirSymlink", root + "/dir1", 0740},
	}

	now := time.Now()
	for _, info := range files {
		p := path.Join(root, info.path)
		if info.filetype == Dir {
			if err := os.MkdirAll(p, info.permissions); err != nil {
				t.Fatal(err)
			}
		} else if info.filetype == Regular {
			if err := ioutil.WriteFile(p, []byte(info.contents), info.permissions); err != nil {
				t.Fatal(err)
			}
		} else if info.filetype == Symlink {
			if err := os.Symlink(info.contents, p); err != nil {
				t.Fatal(err)
			}
		}

		if info.filetype != Symlink {
			// Set a consistent ctime, atime for all files and dirs
			if err := system.Chtimes(p, now, now); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestChangeString(t *testing.T) {
	modifyChange := Change{"change", ChangeModify}
	toString := modifyChange.String()
	if toString != "C change" {
		t.Fatalf("String() of a change with ChangeModify Kind should have been %s but was %s", "C change", toString)
	}
	addChange := Change{"change", ChangeAdd}
	toString = addChange.String()
	if toString != "A change" {
		t.Fatalf("String() of a change with ChangeAdd Kind should have been %s but was %s", "A change", toString)
	}
	deleteChange := Change{"change", ChangeDelete}
	toString = deleteChange.String()
	if toString != "D change" {
		t.Fatalf("String() of a change with ChangeDelete Kind should have been %s but was %s", "D change", toString)
	}
}

func TestChangesWithNoChanges(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows")
	}
	rwLayer, err := ioutil.TempDir("", "docker-changes-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rwLayer)
	layer, err := ioutil.TempDir("", "docker-changes-test-layer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(layer)
	createSampleDir(t, layer)
	changes, err := Changes([]string{layer}, rwLayer)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("Changes with no difference should have detect no changes, but detected %d", len(changes))
	}
}

func TestChangesWithChanges(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows")
	}
	// Mock the readonly layer
	layer, err := ioutil.TempDir("", "docker-changes-test-layer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(layer)
	createSampleDir(t, layer)
	os.MkdirAll(path.Join(layer, "dir1/subfolder"), 0740)

	// Mock the RW layer
	rwLayer, err := ioutil.TempDir("", "docker-changes-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rwLayer)

	// Create a folder in RW layer
	dir1 := path.Join(rwLayer, "dir1")
	os.MkdirAll(dir1, 0740)
	deletedFile := path.Join(dir1, ".wh.file1-2")
	ioutil.WriteFile(deletedFile, []byte{}, 0600)
	modifiedFile := path.Join(dir1, "file1-1")
	ioutil.WriteFile(modifiedFile, []byte{0x00}, 01444)
	// Let's add a subfolder for a newFile
	subfolder := path.Join(dir1, "subfolder")
	os.MkdirAll(subfolder, 0740)
	newFile := path.Join(subfolder, "newFile")
	ioutil.WriteFile(newFile, []byte{}, 0740)

	changes, err := Changes([]string{layer}, rwLayer)
	if err != nil {
		t.Fatal(err)
	}

	expectedChanges := []Change{
		{"/dir1", ChangeModify},
		{"/dir1/file1-1", ChangeModify},
		{"/dir1/file1-2", ChangeDelete},
		{"/dir1/subfolder", ChangeModify},
		{"/dir1/subfolder/newFile", ChangeAdd},
	}
	checkChanges(expectedChanges, changes, t)
}

// See https://github.com/docker/docker/pull/13590
func TestChangesWithChangesGH13590(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	if runtime.GOOS == "windows" {
		t.Skip("symlinks on Windows")
	}
	baseLayer, err := ioutil.TempDir("", "docker-changes-test.")
	defer os.RemoveAll(baseLayer)

	dir3 := path.Join(baseLayer, "dir1/dir2/dir3")
	os.MkdirAll(dir3, 07400)

	file := path.Join(dir3, "file.txt")
	ioutil.WriteFile(file, []byte("hello"), 0666)

	layer, err := ioutil.TempDir("", "docker-changes-test2.")
	defer os.RemoveAll(layer)

	// Test creating a new file
	if err := copyDir(baseLayer+"/dir1", layer+"/"); err != nil {
		t.Fatalf("Cmd failed: %q", err)
	}

	os.Remove(path.Join(layer, "dir1/dir2/dir3/file.txt"))
	file = path.Join(layer, "dir1/dir2/dir3/file1.txt")
	ioutil.WriteFile(file, []byte("bye"), 0666)

	changes, err := Changes([]string{baseLayer}, layer)
	if err != nil {
		t.Fatal(err)
	}

	expectedChanges := []Change{
		{"/dir1/dir2/dir3", ChangeModify},
		{"/dir1/dir2/dir3/file1.txt", ChangeAdd},
	}
	checkChanges(expectedChanges, changes, t)

	// Now test changing a file
	layer, err = ioutil.TempDir("", "docker-changes-test3.")
	defer os.RemoveAll(layer)

	if err := copyDir(baseLayer+"/dir1", layer+"/"); err != nil {
		t.Fatalf("Cmd failed: %q", err)
	}

	file = path.Join(layer, "dir1/dir2/dir3/file.txt")
	ioutil.WriteFile(file, []byte("bye"), 0666)

	changes, err = Changes([]string{baseLayer}, layer)
	if err != nil {
		t.Fatal(err)
	}

	expectedChanges = []Change{
		{"/dir1/dir2/dir3/file.txt", ChangeModify},
	}
	checkChanges(expectedChanges, changes, t)
}

// Create a directory, copy it, make sure we report no changes between the two
func TestChangesDirsEmpty(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	// TODO Should work for Solaris
	if runtime.GOOS == "windows" || runtime.GOOS == "solaris" {
		t.Skip("symlinks on Windows; gcp failure on Solaris")
	}
	src, err := ioutil.TempDir("", "docker-changes-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(src)
	createSampleDir(t, src)
	dst := src + "-copy"
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dst)
	changes, err := ChangesDirs(dst, src)
	if err != nil {
		t.Fatal(err)
	}

	if len(changes) != 0 {
		t.Fatalf("Reported changes for identical dirs: %v", changes)
	}
	os.RemoveAll(src)
	os.RemoveAll(dst)
}

func mutateSampleDir(t *testing.T, root string) {
	// Remove a regular file
	if err := os.RemoveAll(path.Join(root, "file1")); err != nil {
		t.Fatal(err)
	}

	// Remove a directory
	if err := os.RemoveAll(path.Join(root, "dir1")); err != nil {
		t.Fatal(err)
	}

	// Remove a symlink
	if err := os.RemoveAll(path.Join(root, "symlink1")); err != nil {
		t.Fatal(err)
	}

	// Rewrite a file
	if err := ioutil.WriteFile(path.Join(root, "file2"), []byte("fileNN\n"), 0777); err != nil {
		t.Fatal(err)
	}

	// Replace a file
	if err := os.RemoveAll(path.Join(root, "file3")); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(root, "file3"), []byte("fileMM\n"), 0404); err != nil {
		t.Fatal(err)
	}

	// Touch file
	if err := system.Chtimes(path.Join(root, "file4"), time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	// Replace file with dir
	if err := os.RemoveAll(path.Join(root, "file5")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path.Join(root, "file5"), 0666); err != nil {
		t.Fatal(err)
	}

	// Create new file
	if err := ioutil.WriteFile(path.Join(root, "filenew"), []byte("filenew\n"), 0777); err != nil {
		t.Fatal(err)
	}

	// Create new dir
	if err := os.MkdirAll(path.Join(root, "dirnew"), 0766); err != nil {
		t.Fatal(err)
	}

	// Create a new symlink
	if err := os.Symlink("targetnew", path.Join(root, "symlinknew")); err != nil {
		t.Fatal(err)
	}

	// Change a symlink
	if err := os.RemoveAll(path.Join(root, "symlink2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target2change", path.Join(root, "symlink2")); err != nil {
		t.Fatal(err)
	}

	// Replace dir with file
	if err := os.RemoveAll(path.Join(root, "dir2")); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(root, "dir2"), []byte("dir2\n"), 0777); err != nil {
		t.Fatal(err)
	}

	// Touch dir
	if err := system.Chtimes(path.Join(root, "dir3"), time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestChangesDirsMutated(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	// TODO Should work for Solaris
	if runtime.GOOS == "windows" || runtime.GOOS == "solaris" {
		t.Skip("symlinks on Windows; gcp failures on Solaris")
	}
	src, err := ioutil.TempDir("", "docker-changes-test")
	if err != nil {
		t.Fatal(err)
	}
	createSampleDir(t, src)
	dst := src + "-copy"
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(src)
	defer os.RemoveAll(dst)

	mutateSampleDir(t, dst)

	changes, err := ChangesDirs(dst, src)
	if err != nil {
		t.Fatal(err)
	}

	sort.Sort(changesByPath(changes))

	expectedChanges := []Change{
		{"/dir1", ChangeDelete},
		{"/dir2", ChangeModify},
		{"/dirnew", ChangeAdd},
		{"/file1", ChangeDelete},
		{"/file2", ChangeModify},
		{"/file3", ChangeModify},
		{"/file4", ChangeModify},
		{"/file5", ChangeModify},
		{"/filenew", ChangeAdd},
		{"/symlink1", ChangeDelete},
		{"/symlink2", ChangeModify},
		{"/symlinknew", ChangeAdd},
	}

	for i := 0; i < max(len(changes), len(expectedChanges)); i++ {
		if i >= len(expectedChanges) {
			t.Fatalf("unexpected change %s\n", changes[i].String())
		}
		if i >= len(changes) {
			t.Fatalf("no change for expected change %s\n", expectedChanges[i].String())
		}
		if changes[i].Path == expectedChanges[i].Path {
			if changes[i] != expectedChanges[i] {
				t.Fatalf("Wrong change for %s, expected %s, got %s\n", changes[i].Path, changes[i].String(), expectedChanges[i].String())
			}
		} else if changes[i].Path < expectedChanges[i].Path {
			t.Fatalf("unexpected change %s\n", changes[i].String())
		} else {
			t.Fatalf("no change for expected change %s != %s\n", expectedChanges[i].String(), changes[i].String())
		}
	}
}

func TestApplyLayer(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	// TODO Should work for Solaris
	if runtime.GOOS == "windows" || runtime.GOOS == "solaris" {
		t.Skip("symlinks on Windows; gcp failures on Solaris")
	}
	src, err := ioutil.TempDir("", "docker-changes-test")
	if err != nil {
		t.Fatal(err)
	}
	createSampleDir(t, src)
	defer os.RemoveAll(src)
	dst := src + "-copy"
	if err := copyDir(src, dst); err != nil {
		t.Fatal(err)
	}
	mutateSampleDir(t, dst)
	defer os.RemoveAll(dst)

	changes, err := ChangesDirs(dst, src)
	if err != nil {
		t.Fatal(err)
	}

	layer, err := ExportChanges(dst, changes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	layerCopy, err := NewTempArchive(layer, "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ApplyLayer(src, layerCopy); err != nil {
		t.Fatal(err)
	}

	changes2, err := ChangesDirs(src, dst)
	if err != nil {
		t.Fatal(err)
	}

	if len(changes2) != 0 {
		t.Fatalf("Unexpected differences after reapplying mutation: %v", changes2)
	}
}

func TestChangesSizeWithHardlinks(t *testing.T) {
	// TODO Windows. There may be a way of running this, but turning off for now
	// as createSampleDir uses symlinks.
	if runtime.GOOS == "windows" {
		t.Skip("hardlinks on Windows")
	}
	srcDir, err := ioutil.TempDir("", "docker-test-srcDir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(srcDir)

	destDir, err := ioutil.TempDir("", "docker-test-destDir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(destDir)

	creationSize, err := prepareUntarSourceDirectory(100, destDir, true)
	if err != nil {
		t.Fatal(err)
	}

	changes, err := ChangesDirs(destDir, srcDir)
	if err != nil {
		t.Fatal(err)
	}

	got := ChangesSize(destDir, changes)
	if got != int64(creationSize) {
		t.Errorf("Expected %d bytes of changes, got %d", creationSize, got)
	}
}

func TestChangesSizeWithNoChanges(t *testing.T) {
	size := ChangesSize("/tmp", nil)
	if size != 0 {
		t.Fatalf("ChangesSizes with no changes should be 0, was %d", size)
	}
}

func TestChangesSizeWithOnlyDeleteChanges(t *testing.T) {
	changes := []Change{
		{Path: "deletedPath", Kind: ChangeDelete},
	}
	size := ChangesSize("/tmp", changes)
	if size != 0 {
		t.Fatalf("ChangesSizes with only delete changes should be 0, was %d", size)
	}
}

func TestChangesSize(t *testing.T) {
	parentPath, err := ioutil.TempDir("", "docker-changes-test")
	defer os.RemoveAll(parentPath)
	addition := path.Join(parentPath, "addition")
	if err := ioutil.WriteFile(addition, []byte{0x01, 0x01, 0x01}, 0744); err != nil {
		t.Fatal(err)
	}
	modification := path.Join(parentPath, "modification")
	if err = ioutil.WriteFile(modification, []byte{0x01, 0x01, 0x01}, 0744); err != nil {
		t.Fatal(err)
	}
	changes := []Change{
		{Path: "addition", Kind: ChangeAdd},
		{Path: "modification", Kind: ChangeModify},
	}
	size := ChangesSize(parentPath, changes)
	if size != 6 {
		t.Fatalf("Expected 6 bytes of changes, got %d", size)
	}
}

func checkChanges(expectedChanges, changes []Change, t *testing.T) {
	sort.Sort(changesByPath(expectedChanges))
	sort.Sort(changesByPath(changes))
	for i := 0; i < max(len(changes), len(expectedChanges)); i++ {
		if i >= len(expectedChanges) {
			t.Fatalf("unexpected change %s\n", changes[i].String())
		}
		if i >= len(changes) {
			t.Fatalf("no change for expected change %s\n", expectedChanges[i].String())
		}
		if changes[i].Path == expectedChanges[i].Path {
			if changes[i] != expectedChanges[i] {
				t.Fatalf("Wrong change for %s, expected %s, got %s\n", changes[i].Path, changes[i].String(), expectedChanges[i].String())
			}
		} else if changes[i].Path < expectedChanges[i].Path {
			t.Fatalf("unexpected change %s\n", changes[i].String())
		} else {
			t.Fatalf("no change for expected change %s != %s\n", expectedChanges[i].String(), changes[i].String())
		}
	}
}
