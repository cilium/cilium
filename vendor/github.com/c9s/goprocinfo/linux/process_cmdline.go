package linux

import (
	"io/ioutil"
	"strings"
)

func ReadProcessCmdline(path string) (string, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return "", err
	}

	l := len(b) - 1 // Define limit before last byte ('\0')
	z := byte(0)    // '\0' or null byte
	s := byte(0x20) // space byte
	c := 0          // cursor of useful bytes

	for i := 0; i < l; i++ {

		// Check if next byte is not a '\0' byte.
		if b[i+1] != z {

			// Offset must match a '\0' byte.
			c = i + 2

			// If current byte is '\0', replace it with a space byte.
			if b[i] == z {
				b[i] = s
			}
		}
	}

	x := strings.TrimSpace(string(b[0:c]))

	return x, nil
}
