package daemon

import (
	"time"

	"github.com/noironetworks/cilium-net/common"

	consulAPI "github.com/hashicorp/consul/api"
)

// EnableConsulWatcher watches for consul changes in the common.LastFreeIDKeyPath key.
// Triggers policy updates every time the value of that key is changed.
func (d *Daemon) EnableConsulWatcher(maxSeconds time.Duration) {
	go func() {
		curSeconds := time.Second
		var (
			k   *consulAPI.KVPair
			q   *consulAPI.QueryMeta
			qo  consulAPI.QueryOptions
			err error
		)
		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, nil)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k != nil {
				break
			} else {
				log.Debugf("Unable to retreive last free Index, please start some containers with labels.")
			}
			time.Sleep(maxSeconds)
		}

		for {
			k, q, err = d.consul.KV().Get(common.LastFreeIDKeyPath, &qo)
			if err != nil {
				log.Errorf("Unable to retreive last free Index: %s", err)
			}
			if k == nil || q == nil {
				log.Warning("Unable to retreive last free Index, please start some containers with labels.")
				time.Sleep(curSeconds)
				if curSeconds < maxSeconds {
					curSeconds += time.Second
				}
				continue
			}
			curSeconds = time.Second
			qo.WaitIndex = q.LastIndex
			go func() {
				d.triggerPolicyUpdates([]uint32{})
			}()
		}
	}()
}
