package daemon

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	dockerAPI "github.com/docker/engine-api/client"
)

// SyncState syncs cilium state against the containers running in the host. dir is the
// cilium's running directory. If clean is set, the endpoints that don't have its
// container in running state are deleted.
func (d *Daemon) SyncState(dir string, clean bool) error {
	log.Info("Syncing state...")
	d.endpointsMU.Lock()
	if dir == "" {
		dir = common.CiliumPath
	}
	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		d.endpointsMU.Unlock()
		return err
	}
	eptsID := types.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Debug("Endpoints not found. Starting as clean state.")
		d.endpointsMU.Unlock()
		return nil
	}

	for _, ep := range possibleEPs {
		if !isValidID(ep.ID) {
			log.Warningf("Endpoint %q has an invalid ID, it won't be restored.")
			continue
		}
		if err := d.syncLabels(ep); err != nil {
			log.Warningf("%s", err)
		}
		d.insertEndpoint(ep)
		log.Infof("Successfully restored endpoint: %s\n", ep.ID)
	}

	d.endpointsMU.Unlock()

	if clean {
		d.cleanUpDockerDandlingEndpoints()
	}

	// TODO: do a clean up for kubernetes containers?

	eps, err := d.EndpointsGet()
	for _, ep := range eps {
		d.EndpointUpdate(ep.ID, nil)
	}

	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory names that
// possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*types.Endpoint {
	possibleEPs := []*types.Endpoint{}
	for _, epID := range eptsDirNames {
		epDir := filepath.Join(basePath, epID)
		log.Debugf("Reading directory %s\n", epDir)
		epFiles, err := ioutil.ReadDir(epDir)
		if err != nil {
			log.Warningf("Error while reading directory %q. Ignoring it...", epDir)
			continue
		}
		cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
		if cHeaderFile == "" {
			log.Infof("File %q not found in %q. Ignoring endpoint %q.",
				common.CHeaderFileName, epDir, epID)
			continue
		}
		log.Debugf("Found endpoint C header file %q\n", cHeaderFile)
		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		ep, err := types.ParseEndpoint(strEp)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

// syncLabels syncs the labels from the labels' database for the given endpoint. To be
// used with endpointsMU locked.
func (d *Daemon) syncLabels(ep *types.Endpoint) error {
	if ep.SecLabel == nil {
		return fmt.Errorf("Endpoint doesn't have a security label.")
	}
	sha256sum, err := ep.SecLabel.Labels.SHA256Sum()
	if err != nil {
		return fmt.Errorf("Unable to get the sha256sum of labels: %+v\n", ep.SecLabel.Labels)
	}

	labels, err := d.GetLabelsBySHA256(sha256sum)
	if err != nil {
		return fmt.Errorf("Unable to get labels of sha256sum:%s: %+v\n", sha256sum, err)
	}

	if labels == nil {
		labels, _, err = d.PutLabels(ep.SecLabel.Labels)
		if err != nil {
			return fmt.Errorf("Unable to put labels %+v: %s\n", ep.SecLabel.Labels, err)
		}
	}

	if !reflect.DeepEqual(labels.Labels, ep.SecLabel.Labels) {
		return fmt.Errorf("The set of labels should be the same for " +
			"the endpoint being restored and the labels stored")
	}

	if labels.ID != ep.SecLabel.ID {
		log.Infof("Security label ID for endpoint %s is different "+
			"that the one stored, updating from %d to %d\n",
			ep.ID, ep.SecLabel.ID, labels.ID)
	}
	ep.SetSecLabel(labels)
	return nil
}

// cleanUpDockerDandlingEndpoints cleans all endpoints that are dandling by checking out
// if a particular endpoint has its container running.
func (d *Daemon) cleanUpDockerDandlingEndpoints() {
	eps, _ := d.EndpointsGet()
	if eps == nil {
		return
	}

	cleanUp := func(epID string) {
		log.Infof("Endpoint %q not found in docker, cleaning up...", epID)
		d.EndpointLeave(epID)
	}

	for _, ep := range eps {
		log.Debugf("Checking if endpoint is running in docker %s", ep.ID)
		if ep.DockerNetworkID != "" {
			nls, err := d.dockerClient.NetworkInspect(ep.DockerNetworkID)
			if dockerAPI.IsErrNetworkNotFound(err) {
				cleanUp(ep.ID)
				continue
			}
			if err != nil {
				continue
			}
			found := false
			for _, v := range nls.Containers {
				if v.EndpointID == ep.DockerEndpointID {
					found = true
					break
				}
			}
			if !found {
				cleanUp(ep.ID)
				continue
			}
		} else if ep.DockerID != "" {
			cont, err := d.dockerClient.ContainerInspect(ep.DockerID)
			if dockerAPI.IsErrContainerNotFound(err) {
				cleanUp(ep.ID)
				continue
			}
			if err != nil {
				continue
			}
			if !cont.State.Running {
				cleanUp(ep.ID)
				continue
			}
		} else {
			cleanUp(ep.ID)
			continue
		}
	}
}
