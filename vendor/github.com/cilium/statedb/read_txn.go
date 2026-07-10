package statedb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

type readTxn []*tableEntry

func (r *readTxn) getTableEntry(meta TableMeta) *tableEntry {
	return (*r)[meta.tablePos()]
}

// indexReadTxn implements ReadTxn.
func (r *readTxn) indexReadTxn(meta TableMeta, indexPos int) (tableIndexReader, error) {
	if meta.tablePos() < 0 {
		return nil, tableError(meta.Name(), ErrTableNotRegistered)
	}
	return (*r)[meta.tablePos()].indexes[indexPos], nil
}

// mustIndexReadTxn implements ReadTxn.
func (r readTxn) mustIndexReadTxn(meta TableMeta, indexPos int) tableIndexReader {
	indexTxn, err := r.indexReadTxn(meta, indexPos)
	if err != nil {
		panic(err)
	}
	return indexTxn
}

// root implements ReadTxn.
func (r *readTxn) root() dbRoot {
	return dbRoot(*r)
}

// committedRoot implements ReadTxn.
func (r *readTxn) committedRoot() dbRoot {
	return dbRoot(*r)
}

// WriteJSON marshals out the database as JSON into the given writer.
// If tables are given then only these tables are written.
func (r *readTxn) WriteJSON(w io.Writer, tables ...string) error {
	buf := bufio.NewWriter(w)
	buf.WriteString("{\n")
	first := true
	for _, table := range *r {
		if len(tables) > 0 && !slices.Contains(tables, table.meta.Name()) {
			continue
		}
		if !first {
			buf.WriteString(",\n")
		} else {
			first = false
		}

		if err := writeTableAsJSON(buf, r, table); err != nil {
			return err
		}
	}
	if !first {
		buf.WriteString("\n}\n")
	} else {
		buf.WriteString("}\n")
	}
	return buf.Flush()
}

var _ ReadTxn = &readTxn{}

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
	iter, _ := indexTxn.all()

	writeString := func(s string) {
		if err != nil {
			return
		}
		_, err = buf.WriteString(s)
	}
	writeString("  \"" + table.meta.Name() + "\": [\n")

	numObjects := indexTxn.len()

	for _, obj := range iter.All {
		writeString("    ")
		if _, err := buf.Write(marshalJSON(obj.data)); err != nil {
			return err
		}
		numObjects--
		if numObjects > 0 {
			writeString(",\n")
		} else {
			writeString("\n")
		}
	}
	writeString("  ]")
	return
}
