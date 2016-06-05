package daemon

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/noironetworks/cilium-net/common/types"

	"k8s.io/kubernetes/pkg/watch"
)

type networkPolicyWatchEvent struct {
	Type   watch.EventType     `json:"type"`
	Object types.NetworkPolicy `json:"object"`
}

func (d *Daemon) EnableK8sWatcher(maxSeconds time.Duration) error {
	curSeconds := 2 * time.Second

	u := d.k8sClient.Get().RequestURI("apis/experimental.kubernetes.io/v1").
		Namespace("default").Resource("networkpolicys").Param("watch", "true").URL()
	go func() {
		reportError := true
		makeRequest := func() *http.Response {
			for {
				resp, err := http.Get(u.String())
				if err != nil {
					if reportError {
						log.Warningf("Unable to intall k8s watcher for URL %s: %s", u, err)
						reportError = false
					}
				} else if resp.StatusCode == http.StatusOK {
					// Once connected, report new errors again
					reportError = true
					return resp
				}
				time.Sleep(curSeconds)
				if curSeconds < maxSeconds {
					curSeconds = 2 * curSeconds
				}
			}
		}
		resp := makeRequest()
		curSeconds = time.Second
		log.Info("Now listening for kubernetes network policys changes")
		for {
			npwe := networkPolicyWatchEvent{}
			err := json.NewDecoder(resp.Body).Decode(&npwe)
			if err != nil {
				log.Errorf("Error while receiving data %s", err)
				resp.Body.Close()
				resp = makeRequest()
				curSeconds = time.Second
				continue
			}
			log.Debugf("Received kubernetes network policy %+v\n", npwe)
			go d.processNPE(npwe)
		}
	}()
	return nil
}

func (d *Daemon) processNPE(npwe networkPolicyWatchEvent) {
	nodePath, pn, err := types.K8sNP2CP(npwe.Object)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", npwe.Object, err)
		return
	}
	switch npwe.Type {
	case watch.Added, watch.Modified:
		if err := d.PolicyAdd(nodePath, pn); err != nil {
			log.Errorf("Error while adding kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Info("Kubernetes network policy successfully add")
	case watch.Deleted:
		if err := d.PolicyDelete(nodePath); err != nil {
			log.Errorf("Error while deleting kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Info("Kubernetes network policy successfully removed")
	}
}
