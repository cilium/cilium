package common

import (
	"fmt"
)

func GoArray2C(array []byte) string {
	ret := "{ "

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(", %#x", e)
		}
	}

	return ret + " }"
}

func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = %s }\n", name, GoArray2C(addr))
}

func FmtDefineArray(name string, array []byte) string {
	return fmt.Sprintf("#define %s %s\n", name, GoArray2C(array))
}
