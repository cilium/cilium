package parser

import (
	"fmt"
	"os"
	"path"
	"strings"
)

func normalizePath(path string) string {
	return strings.Replace(path, "\\", "/", -1)
}

func getPkgPath(fname string) (string, error) {
	if !path.IsAbs(fname) {
		pwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		fname = path.Join(pwd, fname)
	}

	fname = normalizePath(fname)

	for _, p := range strings.Split(os.Getenv("GOPATH"), ";") {
		prefix := path.Join(normalizePath(p), "src") + "/"
		if rel := strings.TrimPrefix(fname, prefix); rel != fname {
			return path.Dir(rel), nil
		}
	}

	return "", fmt.Errorf("file '%v' is not in GOPATH", fname)
}
