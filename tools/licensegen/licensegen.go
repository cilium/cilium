// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	err := filepath.Walk("./vendor", func(path string, _ os.FileInfo, _ error) error {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		if stem := strings.TrimSuffix(base, ext); stem == "LICENSE" || stem == "COPYING" {
			switch strings.TrimPrefix(strings.ToLower(ext), ".") {
			case "", "code", "docs", "libyaml", "md", "txt":
				fmt.Println("Name:", path)
				lb, err := os.ReadFile(path)
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
