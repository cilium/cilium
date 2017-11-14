package linux

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func ReadMaxPID(path string) (uint64, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return 0, err
	}

	s := strings.TrimSpace(string(b))

	i, err := strconv.ParseUint(s, 10, 64)

	if err != nil {
		return 0, err
	}

	return i, nil

}

func ListPID(path string, max uint64) ([]uint64, error) {

	l := make([]uint64, 0, 5)

	for i := uint64(1); i <= max; i++ {

		p := filepath.Join(path, strconv.FormatUint(i, 10))

		s, err := os.Stat(p)

		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}

		if err != nil || !s.IsDir() {
			continue
		}

		l = append(l, i)

	}

	return l, nil
}
