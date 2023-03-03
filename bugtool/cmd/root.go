package cmd

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func RemoveObjectFiles(cmdDir, pattern string) {
	// Remove object files for each endpoint. Endpoints directories are in the
	// state directory and have numerical names.
	rmFunc := func(path string) {
		matches, err := filepath.Glob(path)
		if err != nil {
			log.Errorf("Failed to exclude object files: %s", err)
		}
		for _, m := range matches {
			err = os.Remove(m)
			if err != nil {
				log.Errorf("Failed to exclude object file: %s", err)
			}
		}
	}

	path := filepath.Join(cmdDir, pattern)
	rmFunc(path)
}
