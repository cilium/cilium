// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package labelsfilter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/labels"
)

func FuzzLabelsfilterPkg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := fuzz.NewConsumer(data)

		prefixes := make([]string, 0)
		err := f.CreateSlice(&prefixes)
		if err != nil {
			return
		}
		nodePrefixes := make([]string, 0)
		err = f.CreateSlice(&nodePrefixes)
		if err != nil {
			return
		}
		lpc := &labelPrefixCfg{}
		err = f.GenerateStruct(lpc)
		if err != nil {
			return
		}
		lpc.Version = LPCfgFileVersion
		fileBytes, err := json.Marshal(lpc)

		if err != nil {
			return
		}
		stringMap := make(map[string]string)
		err = f.FuzzMap(&stringMap)
		if err != nil {
			return
		}

		source, err := f.GetString()
		if err != nil {
			return
		}

		lbls := labels.Map2Labels(stringMap, source)

		file, err := os.Create("file")
		if err != nil {
			return
		}
		defer file.Close()

		_, err = file.Write(fileBytes)
		if err != nil {
			return
		}

		err = ParseLabelPrefixCfg(slog.New(slog.DiscardHandler), prefixes, nodePrefixes, "file")
		if err != nil {
			fmt.Println(err)
			return
		}
		_, _ = Filter(lbls)
	})
}
