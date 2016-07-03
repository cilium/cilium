package daemon

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/noironetworks/cilium-net/common/types"

	"k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	"k8s.io/kubernetes/pkg/watch"
)

type networkPolicyWatchEvent struct {
	Type   watch.EventType       `json:"type"`
	Object v1beta1.NetworkPolicy `json:"object"`
}

func (d *Daemon) EnableK8sWatcher(maxSeconds time.Duration) error {
	curSeconds := 2 * time.Second
	uNPs := d.k8sClient.Get().RequestURI("apis/extensions/v1beta1").
		Resource("networkpolicies").URL().String()
	uWatcher := d.k8sClient.Get().RequestURI("apis/extensions/v1beta1").
		Namespace("default").Resource("networkpolicies").Param("watch", "true").URL().String()
	go func() {
		reportError := true
		makeRequest := func(url string) *http.Response {
			for {
				resp, err := http.Get(url)
				if err != nil {
					if reportError {
						log.Warningf("Unable to install k8s watcher for URL %s: %s", url, err)
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
		for {
			resp := makeRequest(uNPs)
			curSeconds = time.Second
			log.Info("Receiving all policies stored in kubernetes")
			npList := v1beta1.NetworkPolicyList{}
			err := json.NewDecoder(resp.Body).Decode(&npList)
			if err != nil {
				log.Errorf("Error while receiving data %s", err)
				resp.Body.Close()
				continue
			}
			log.Debugf("Received kubernetes network policies %+v\n", npList)
			for _, np := range npList.Items {
				go d.processNPE(networkPolicyWatchEvent{watch.Added, np})
			}
			resp.Body.Close()

			resp = makeRequest(uWatcher)
			log.Info("Listening for kubernetes network policies events")
			for {
				npwe := networkPolicyWatchEvent{}
				err := json.NewDecoder(resp.Body).Decode(&npwe)
				if err != nil {
					log.Errorf("Error while receiving data %s", err)
					resp.Body.Close()
					break
				}
				log.Debugf("Received kubernetes network policy %+v\n", npwe)
				go d.processNPE(npwe)
			}
		}
	}()
	return nil
}

func (d *Daemon) processNPE(npwe networkPolicyWatchEvent) {
	switch npwe.Type {
	case watch.Added, watch.Modified:
		nodePath, pn, err := types.K8sNP2CP(npwe.Object)
		if err != nil {
			log.Errorf("Error while parsing kubernetes network policy %+v: %s", npwe.Object, err)
			return
		}
		if err := d.PolicyAdd(nodePath, pn); err != nil {
			log.Errorf("Error while adding kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Infof("Kubernetes network policy successfully add %+v", npwe.Object)
	case watch.Deleted:
		nodePath, pn, err := types.K8sNP2CP(npwe.Object)
		if err != nil {
			log.Errorf("Error while parsing kubernetes network policy %+v: %s", npwe.Object, err)
			return
		}
		if err := d.PolicyDelete(nodePath); err != nil {
			log.Errorf("Error while deleting kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Infof("Kubernetes network policy successfully removed %+v", npwe.Object)
	}
}
