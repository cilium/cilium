package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

// Provides information about memory usage, measured in pages.
type ProcessStatm struct {
	Size     uint64 `json:"size"`     // total program size
	Resident uint64 `json:"resident"` // resident set size
	Share    uint64 `json:"share"`    // shared pages
	Text     uint64 `json:"text"`     // text (code)
	Lib      uint64 `json:"lib"`      // library (unused in Linux 2.6)
	Data     uint64 `json:"data"`     // data + stack
	Dirty    uint64 `json:"dirty"`    // dirty pages (unused in Linux 2.6)
}

func ReadProcessStatm(path string) (*ProcessStatm, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	s := string(b)
	f := strings.Fields(s)

	statm := ProcessStatm{}

	var n uint64

	for i := 0; i < len(f); i++ {

		if n, err = strconv.ParseUint(f[i], 10, 64); err != nil {
			return nil, err
		}

		switch i {
		case 0:
			statm.Size = n
		case 1:
			statm.Resident = n
		case 2:
			statm.Share = n
		case 3:
			statm.Text = n
		case 4:
			statm.Lib = n
		case 5:
			statm.Data = n
		case 6:
			statm.Dirty = n
		}

	}

	return &statm, nil
}
