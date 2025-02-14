package namemanager

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/cilium/cilium/pkg/policy/api"
)

func FuzzMapSelectorsToNamesLocked(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		fqdnSelector := api.FQDNSelector{}
		ff.FuzzMap(fqdnSelector)
		nameManager := New(ManagerParams{
			Config: NameManagerConfig{
				MinTTL: 1,
			},
		})
		nameManager.mapSelectorsToNamesLocked(fqdnSelector)
	})
}
