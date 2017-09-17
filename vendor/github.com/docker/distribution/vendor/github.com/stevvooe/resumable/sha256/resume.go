package sha256

import (
	"bytes"
	"crypto"
	"encoding/gob"

	"github.com/stevvooe/resumable"
	// import to ensure that our init function runs after the standard package
	_ "crypto/sha256"
)

// Len returns the number of bytes which have been written to the digest.
func (d *digest) Len() int64 {
	return int64(d.len)
}

// State returns a snapshot of the state of the digest.
func (d *digest) State() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)

	function := crypto.SHA256
	if d.is224 {
		function = crypto.SHA224
	}

	// We encode this way so that we do not have
	// to export these fields of the digest struct.
	vals := []interface{}{
		d.h, d.x, d.nx, d.len, function,
	}

	for _, val := range vals {
		if err := encoder.Encode(val); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Restore resets the digest to the given state.
func (d *digest) Restore(state []byte) error {
	decoder := gob.NewDecoder(bytes.NewReader(state))

	var function uint

	// We decode this way so that we do not have
	// to export these fields of the digest struct.
	vals := []interface{}{
		&d.h, &d.x, &d.nx, &d.len, &function,
	}

	for _, val := range vals {
		if err := decoder.Decode(val); err != nil {
			return err
		}
	}

	switch crypto.Hash(function) {
	case crypto.SHA224:
		d.is224 = true
	case crypto.SHA256:
		d.is224 = false
	default:
		return resumable.ErrBadState
	}

	return nil
}
