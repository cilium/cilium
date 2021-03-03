//+build gofuzz

package ndp

func Fuzz(data []byte) int {
	return fuzz(data)
}
