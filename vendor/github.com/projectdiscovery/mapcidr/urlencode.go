package mapcidr

import (
	"bytes"
)

const upperhex = "0123456789ABCDEF"

func escape(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		b.WriteString("%")
		b.WriteByte(upperhex[s[i]>>4])
		b.WriteByte(upperhex[s[i]&15])
	}
	return b.String()
}
