package linux

import (
	"bufio"
	"os"
	"strings"
)

type Mounts struct {
	Mounts []Mount `json:"mounts"`
}

type Mount struct {
	Device     string `json:"device"`
	MountPoint string `json:"mountpoint"`
	FSType     string `json:"fstype"`
	Options    string `json:"options"`
}

const (
	DefaultBufferSize = 1024
)

func ReadMounts(path string) (*Mounts, error) {
	fin, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fin.Close()

	var mounts = Mounts{}

	scanner := bufio.NewScanner(fin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		var mount = &Mount{
			fields[0],
			fields[1],
			fields[2],
			fields[3],
		}
		mounts.Mounts = append(mounts.Mounts, *mount)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &mounts, nil
}
