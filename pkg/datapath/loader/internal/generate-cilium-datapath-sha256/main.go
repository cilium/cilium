// generate-cilium-datapath-sha256
//
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

func ingestFile(h hash.Hash, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(h, f)
	return err
}

func run() error {
	h := sha256.New()
	for _, arg := range os.Args[1:] {
		if err := ingestFile(h, arg); err != nil {
			return err
		}
	}
	_, err := fmt.Printf(""+
		"package loader\n"+
		"\n"+
		"// DatapathSHA256 is set during build to the SHA across all datapath BPF\n"+
		"// code.\n"+
		"const DatapathSHA256 = %q\n",
		hex.EncodeToString(h.Sum(nil)),
	)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
