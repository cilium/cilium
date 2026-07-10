// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
)

const (
	outFileFlag       = "out"
	outFileFlagShort  = "o"
	formatFlag        = "format"
	formatFlagShort   = "f"
	instanceFlag      = "instance"
	instanceFlagShort = "i"

	tabPadding     = 3
	tabMinWidth    = 5
	tabPaddingChar = ' '
)

type tableJSON struct {
	Columns []string            `json:"columns"`
	Rows    []map[string]string `json:"rows"`
}

func tableJSONfromString(output string) tableJSON {
	lines := strings.FieldsFunc(output, func(c rune) bool {
		return c == '\n'
	})
	table := tableJSON{
		Rows: []map[string]string{},
	}

	for i, line := range lines {
		rows := strings.Split(line, "\t")
		for j, row := range rows {
			if i == 0 {
				table.Columns = append(table.Columns, row)
			} else {
				if j == 0 {
					table.Rows = append(table.Rows, map[string]string{})
				}
				table.Rows[i-1][table.Columns[j]] = row
			}
		}
	}

	return table
}

func addOutFileFlag(fs *pflag.FlagSet) {
	fs.StringP(outFileFlag, outFileFlagShort, "", "File to write to instead of stdout")
}

func addFormatFlag(fs *pflag.FlagSet) {
	fs.StringP(formatFlag, formatFlagShort, "table", "Format to write in (table or table-json)")
}

func addFormatFlagPeers(fs *pflag.FlagSet) {
	fs.StringP(formatFlag, formatFlagShort, "table", "Format to write in (table, table-json, json or detailed)")
}

func getCmdWriter(s *script.State) (writer io.Writer, buf *strings.Builder, f *os.File, err error) {
	fileName := ""
	fileName, err = s.Flags.GetString(outFileFlag)
	if err != nil {
		return
	}

	buf = &strings.Builder{}
	if fileName == "" {
		// will write to string buffer
		writer = buf
	} else {
		// will write to file
		f, err = os.OpenFile(s.Path(fileName), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			err = fmt.Errorf("error opening file %s: %w", fileName, err)
			return
		}
		writer = f
	}

	return
}

func getCmdTabWriter(writer io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(writer, tabMinWidth, 0, tabPadding, tabPaddingChar, 0)
}
