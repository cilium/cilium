// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"

	operatorServer "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
)

var (
	MainCell = cell.Module(
		"main",
		"Main module for generating CRD Lists",
		cell.Invoke(printCRDList),
	)

	Hive = hive.New(
		operatorServer.SpecCell,
		MainCell,
	)
)

var ErrorBreakEarly = fmt.Errorf("break early")

func printCRDList(
	opSpec *operatorServer.Spec,
	shutdown hive.Shutdowner,
) error {
	list := client.CustomResourceDefinitionList()

	crdlist := []string{}

	for _, crd := range list {
		crdlist = append(crdlist, cleanupCRDName(crd.Name))
	}

	slices.Sort(crdlist)

	for idx, name := range crdlist {
		// We need to walk ../../Documentation rst files to look and see if the CRD name is a header in the format of `.. _ <name>:`, if so
		// add `ref:` to the name so it will link to the CRD in the docs.
		err := filepath.WalkDir("./Documentation", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if filepath.Ext(path) == ".rst" {
				match, err := grepFile(path, ".. _"+name+":")
				if err != nil {
					return err
				}
				// We can stop walking the documentation as we already know there is a match, so we send an ErrorBreakEarly and ignore that on the other side
				// as WalkDir will keep running until it returns an error or there are no more files to walk.
				if match {
					// Change the name to a ref also specifically override the link text, as a couple headers add " CRD" to the text which causes the link to not be uniform.
					crdlist[idx] = ":ref:`" + name + "<" + name + ">`"
					return ErrorBreakEarly
				}
			}

			return nil
		})
		if err != nil && !errors.Is(err, ErrorBreakEarly) {
			return err
		}
	}

	f, err := os.Create("Documentation/crdlist.rst")
	if err != nil {
		return err
	}
	defer f.Close()

	for _, name := range crdlist {
		_, err := f.WriteString(fmt.Sprintf("- %s\n", name))
		if err != nil {
			return err
		}
	}

	shutdown.Shutdown()
	return nil
}

// Scan file for string
func grepFile(path, search string) (bool, error) {
	//fmt.Printf("searching %s for %s\n", path, search)
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), search) {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// Remove the /(version) portion from the CRD Name
func cleanupCRDName(name string) string {
	return strings.Split(name, "/")[0]
}

func main() {
	Hive.Run(slog.Default())
}
