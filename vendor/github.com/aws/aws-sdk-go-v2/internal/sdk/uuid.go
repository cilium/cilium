package sdk

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/internal/rand"
)

// UUIDVersion4 returns a Version 4 random UUID from the byte slice provided
func UUIDVersion4() (string, error) {
	b := make([]byte, 16)

	var offset int
	for offset < len(b) {
		n, err := rand.Reader.Read(b[offset:])
		if err != nil {
			return "", fmt.Errorf("unable to get random bytes for UUID, %w", err)
		}
		offset += n
	}

	return uuidVersion4(b), nil
}

func uuidVersion4(u []byte) string {
	// https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_.28random.29
	// 13th character is "4"
	u[6] = (u[6] | 0x40) & 0x4F
	// 17th character is "8", "9", "a", or "b"
	u[8] = (u[8] | 0x80) & 0xBF

	return fmt.Sprintf(`%X-%X-%X-%X-%X`, u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}
