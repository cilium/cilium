package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func main() {
	err := filepath.Walk(
		"./vendor",
		func(path string, info os.FileInfo, err error) error {
			if filepath.Base(path) == "LICENSE" {
				fmt.Println("Name:", path)

				lb, err := ioutil.ReadFile(path)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("License:", string(lb))
			}
			return nil
		},
	)
	if err != nil {
		log.Fatal(err)
	}
}
