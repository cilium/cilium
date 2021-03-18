//+build gofuzz

package netlink

func Fuzz(data []byte) int {
	return fuzzAttributes(data)
	// return fuzzMessage(data)
}

func fuzzAttributes(data []byte) int {
	attrs, err := UnmarshalAttributes(data)
	if err != nil {
		return 0
	}

	if _, err := MarshalAttributes(attrs); err != nil {
		panic(err)
	}

	return 1
}

func fuzzMessage(data []byte) int {
	var m Message
	if err := (&m).UnmarshalBinary(data); err != nil {
		return 0
	}

	if _, err := m.MarshalBinary(); err != nil {
		panic(err)
	}

	return 1
}
