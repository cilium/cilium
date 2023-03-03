package dump

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/ebpf"
)

type Value struct {
	A uint32
	B uint8
}

type Key types.IPv4

func (k Key) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", k[0], k[1], k[2], k[3])
}

func TestBPFMap(t *testing.T) {
	assert := assert.New(t)

	n := fmt.Sprintf("bugtool_test_%d", time.Now().UnixNano())
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       n,
		Pinning:    ebpf.PinByName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(types.IPv4{})),
		ValueSize:  5,
		MaxEntries: 10,
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf/",
	})
	assert.NoError(err)
	p := path.Join("/sys/fs/bpf", n)
	defer os.Remove(p)
	k := Key{10, 0, 0, 1}
	v := Value{
		A: 1234,
		B: 123,
	}
	assert.NoError(m.Put(&k, &v))
	k = Key{10, 0, 0, 2}
	assert.NoError(m.Put(&k, &v))
	tsk := NewPinnedBPFMap[Key, Value](p)
	td := t.TempDir()
	rt := NewContext(td, func(s string, f func(context.Context) error) error {
		return f(context.Background())
	}, time.Second*5)
	tsk.Run(context.Background(), rt)
	fd, err := os.Open(path.Join(td, n+".json"))
	assert.NoError(err)
	defer fd.Close()
	mp := map[string]Value{}
	assert.NoError(json.NewDecoder(fd).Decode(&mp))
	assert.Contains(mp, "10.0.0.1")
	assert.Contains(mp, "10.0.0.2")
	assert.Equal(mp["10.0.0.1"].A, uint32(1234))
	assert.Equal(mp["10.0.0.2"].A, uint32(1234))
}
