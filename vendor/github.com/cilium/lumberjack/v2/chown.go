// +build !linux

package lumberjack

import (
	"os"
)

func chown(_ string, _ os.FileInfo) error {
	return nil
}

func chownWithMode(_ string, _ os.FileInfo, _ os.FileMode) error {
	return nil
}
