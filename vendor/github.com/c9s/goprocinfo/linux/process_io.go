package linux

import (
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
)

// I/O statistics for the process.
type ProcessIO struct {
	RChar               uint64 `json:"rchar" field:"rchar"`                                 // chars read
	WChar               uint64 `json:"wchar" field:"wchar"`                                 // chars written
	Syscr               uint64 `json:"syscr" field:"syscr"`                                 // read syscalls
	Syscw               uint64 `json:"syscw" field:"syscw"`                                 // write syscalls
	ReadBytes           uint64 `json:"read_bytes" field:"read_bytes"`                       // bytes read
	WriteBytes          uint64 `json:"write_bytes" field:"write_bytes"`                     // bytes written
	CancelledWriteBytes uint64 `json:"cancelled_write_bytes" field:"cancelled_write_bytes"` // bytes truncated
}

func ReadProcessIO(path string) (*ProcessIO, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	// Maps a io metric to its value (i.e. rchar --> 100000)
	m := map[string]uint64{}

	io := ProcessIO{}

	lines := strings.Split(string(b), "\n")

	for _, line := range lines {

		if strings.Index(line, ": ") == -1 {
			continue
		}

		l := strings.Split(line, ": ")

		k := l[0]
		v, err := strconv.ParseUint(l[1], 10, 64)

		if err != nil {
			return nil, err
		}

		m[k] = v

	}

	e := reflect.ValueOf(&io).Elem()
	t := e.Type()

	for i := 0; i < e.NumField(); i++ {

		k := t.Field(i).Tag.Get("field")

		v, ok := m[k]

		if ok {
			e.Field(i).SetUint(v)
		}

	}

	return &io, nil
}
