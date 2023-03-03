package dump

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/cilium/ebpf"
)

// NewBPFMap constructs a new BPF map to dump a pinned bpf map file.
func NewPinnedBPFMap[KT fmt.Stringer, VT any](pinnedFile string) *BPFMap[KT, VT] {
	return &BPFMap[KT, VT]{
		base: base{
			Name: path.Base(pinnedFile),
			Kind: "BPFMap",
		},
		PinnedFile: pinnedFile,
	}
}

// BPFMap is a generic type that implements the Task interface
// by dumping bpf maps.
type BPFMap[KT fmt.Stringer, VT any] struct {
	base
	K, V       string
	PinnedFile string
}

type BPFByteBuffer []byte

func (b BPFByteBuffer) String() string { return string(b) }

func (e *BPFMap[KT, VT]) Run(ctx context.Context, runtime Context) error {
	runtime.Submit(e.Identifier(), func(_ context.Context) error {
		var m *ebpf.Map
		var err error

		fd, err := runtime.CreateFile(fmt.Sprintf("%s.json", e.GetName()))
		if err != nil {
			return fmt.Errorf("failed to create file for %q: %w", e.GetName(), err)
		}
		defer fd.Close()

		m, err = ebpf.LoadPinnedMap(e.PinnedFile, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		if err != nil {
			return fmt.Errorf("failed to load pinned map %s: %w", e.PinnedFile, err)
		}

		entries := m.Iterate()
		var key KT
		var value VT
		kvs := map[string]VT{}
		for entries.Next(&key, &value) {
			kvs[key.String()] = value
		}
		if entries.Err() != nil {
			return fmt.Errorf("failed to iterate map entries: %w", entries.Err())
		}

		if err := json.NewEncoder(fd).Encode(kvs); err != nil {
			return fmt.Errorf("failed to encode map: %w", err)
		}
		return nil
	})
	return nil
}

func (e *BPFMap[KT, VT]) Validate(context.Context) error {
	return nil
}
