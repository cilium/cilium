package licenses

import (
	"embed"
	"io/fs"
)

//go:embed *.db *.txt
var licenseFS embed.FS

// ReadLicenseFile locates and reads the license archive file.  Absolute paths are used unmodified.  Relative paths are expected to be in the licenses directory of the licenseclassifier package.
func ReadLicenseFile(filename string) ([]byte, error) {
	return licenseFS.ReadFile(filename)
}

// ReadLicenseDir reads directory containing the license files.
func ReadLicenseDir() ([]fs.DirEntry, error) {
	return licenseFS.ReadDir(".")
}
