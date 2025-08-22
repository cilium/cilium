// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package labelsfilter

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/labels"
)

func FuzzLabelsfilterPkg(data []byte) int {
	f := fuzz.NewConsumer(data)

	prefixes := make([]string, 0)
	err := f.CreateSlice(&prefixes)
	if err != nil {
		return 0
	}
	lpc := &labelPrefixCfg{}
	err = f.GenerateStruct(lpc)
	if err != nil {
		return 0
	}
	lpc.Version = LPCfgFileVersion
	fileBytes, err := json.Marshal(lpc)

	if err != nil {
		return 0
	}
	stringMap := make(map[string]string)
	err = f.FuzzMap(&stringMap)
	if err != nil {
		return 0
	}

	source, err := f.GetString()
	if err != nil {
		return 0
	}

	lbls := labels.Map2Labels(stringMap, source)

	file, err := os.Create("file")
	defer file.Close()
	if err != nil {
		return 0
	}

	_, err = file.Write(fileBytes)
	if err != nil {
		return 0
	}

	err = ParseLabelPrefixCfg(slog.New(slog.DiscardHandler), prefixes, nil, "file")
	if err != nil {
		fmt.Println(err)
		return 0
	}
	_, _ = Filter(lbls)
	return 1
}
