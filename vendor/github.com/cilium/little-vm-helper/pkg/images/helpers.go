package images

import "path/filepath"

func imageFormatFromFname(fname string) string {
	ext := filepath.Ext(fname)
	switch ext {
	case ".raw", ".iso":
		return "raw"
	case ".qcow2":
		return "qcow2"
	default:
		return "raw"
	}
}
