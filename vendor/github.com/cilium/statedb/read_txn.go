package statedb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

type readTxn []tableEntry

func (r readTxn) getTableEntry(meta TableMeta) *tableEntry {
	return &r[meta.tablePos()]
}

// indexReadTxn implements ReadTxn.
func (r readTxn) indexReadTxn(meta TableMeta, indexPos int) (indexReadTxn, error) {
	if meta.tablePos() < 0 {
		return indexReadTxn{}, tableError(meta.Name(), ErrTableNotRegistered)
	}
	indexEntry := r[meta.tablePos()].indexes[indexPos]
	return indexReadTxn{indexEntry.tree, indexEntry.unique}, nil
}

// mustIndexReadTxn implements ReadTxn.
func (r readTxn) mustIndexReadTxn(meta TableMeta, indexPos int) indexReadTxn {
	indexTxn, err := r.indexReadTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

// root implements ReadTxn.
func (r readTxn) root() dbRoot {
	return dbRoot(r)
}

// WriteJSON marshals out the database as JSON into the given writer.
// If tables are given then only these tables are written.
func (txn readTxn) WriteJSON(w io.Writer, tables ...string) error {
	buf := bufio.NewWriter(w)
	buf.WriteString("{\n")
	first := true

	for _, table := range txn {
		if len(tables) > 0 && !slices.Contains(tables, table.meta.Name()) {
			continue
		}

		if !first {
			buf.WriteString(",\n")
		} else {
			first = false
		}

		if err := writeTableAsJSON(buf, txn, &table); err != nil {
			return err
		}
	}
	buf.WriteString("\n}\n")
	return buf.Flush()
}

var _ ReadTxn = readTxn{}

func marshalJSON(data any) (out []byte) {
	// Catch panics from JSON marshalling to ensure we have some output for debugging
	// purposes even if the object has panicing JSON marshalling.
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Appendf(nil, "\"panic marshalling JSON: %.32s\"", r)
		}
	}()
	bs, err := json.Marshal(data)
	if err != nil {
		return []byte("\"marshalling error: " + err.Error() + "\"")
	}
	return bs
}

func writeTableAsJSON(buf *bufio.Writer, txn ReadTxn, table *tableEntry) (err error) {
	indexTxn := txn.mustIndexReadTxn(table.meta, PrimaryIndexPos)
	iter := indexTxn.Iterator()

	writeString := func(s string) {
		if err != nil {
			return
		}
		_, err = buf.WriteString(s)
	}
	writeString("  \"" + table.meta.Name() + "\": [\n")

	_, obj, ok := iter.Next()
	for ok {
		writeString("    ")
		if _, err := buf.Write(marshalJSON(obj.data)); err != nil {
			return err
		}
		_, obj, ok = iter.Next()
		if ok {
			writeString(",\n")
		} else {
			writeString("\n")
		}
	}
	writeString("  ]")
	return
}
