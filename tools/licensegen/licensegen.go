package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	err := filepath.Walk("./vendor", func(path string, _ os.FileInfo, _ error) error {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		if strings.TrimSuffix(base, ext) == "LICENSE" {
			switch strings.TrimPrefix(strings.ToLower(ext), ".") {
			case "", "code", "docs", "libyaml", "md", "txt":
				fmt.Println("Name:", path)
				lb, err := ioutil.ReadFile(path)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("License:", string(lb))
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
