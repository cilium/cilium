// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type policyWatcher struct {
	log            *slog.Logger
	config         Config
	policyImporter policycell.PolicyImporter
	clusterName    string
	synced         sync.WaitGroup
	// maps cnp file name to cnp object. this is required to retrieve data during delete.
	fileNameToCnpCache map[string]*cilium_v2.CiliumNetworkPolicy
}

func (p *policyWatcher) translateToCNPObject(data []byte) (*cilium_v2.CiliumNetworkPolicy, error) {
	// yaml to json conversion
	jsonData, err := yaml.YAMLToJSON([]byte(data))
	if err != nil {
		return nil, err
	}

	// translate json to cnp object
	cnp := &cilium_v2.CiliumNetworkPolicy{}
	err = json.Unmarshal(jsonData, cnp)
	if err != nil {
		return nil, err
	}
	return cnp, err
}

func (p *policyWatcher) readAndTranslateToCNPObject(file string) (*cilium_v2.CiliumNetworkPolicy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	cnp, err := p.translateToCNPObject(data)
	return cnp, err
}

func getLabels(fileName string, cnp *cilium_v2.CiliumNetworkPolicy) labels.LabelArray {
	labelsArr := labels.LabelArray{
		labels.NewLabel("filename", fileName, labels.LabelSourceDirectory),
	}

	ns := cnp.ObjectMeta.Namespace
	// For clusterwide policy namespace will be empty.
	if ns != "" {
		nsLabel := labels.NewLabel(k8sConst.PolicyLabelNamespace, ns, labels.LabelSourceDirectory)
		labelsArr = append(labelsArr, nsLabel)
		srcLabel := labels.NewLabel("policy-derived-from", k8sCiliumUtils.ResourceTypeCiliumNetworkPolicy, labels.LabelSourceDirectory)
		labelsArr = append(labelsArr, srcLabel)
	} else {
		srcLabel := labels.NewLabel("policy-derived-from", k8sCiliumUtils.ResourceTypeCiliumClusterwideNetworkPolicy, labels.LabelSourceDirectory)
		labelsArr = append(labelsArr, srcLabel)
	}

	return labelsArr
}

// read cilium network policy yaml file and convert to policy object and
// add rules to policy engine.
func (p *policyWatcher) addToPolicyEngine(cnp *cilium_v2.CiliumNetworkPolicy, cnpFilePath string) error {
	fileName := filepath.Base(cnpFilePath)

	resourceID := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindFile,
		p.config.StaticCNPPath,
		fileName,
	)

	// convert to rules
	rules, err := cnp.Parse(p.log, p.clusterName)
	if err != nil {
		return err
	}

	// update labels
	lbls := getLabels(fileName, cnp)
	for _, r := range rules {
		r.Labels = lbls
	}

	dc := make(chan uint64, 1)
	// add to policy engine
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:               rules,
		Source:              source.Directory,
		Resource:            resourceID,
		ProcessingStartTime: time.Now(),
		DoneChan:            dc,
	})
	<-dc // wait for policy to be applied

	p.fileNameToCnpCache[fileName] = cnp

	return err
}

func (p *policyWatcher) deleteFromPolicyEngine(cnpFilePath string) error {
	fileName := filepath.Base(cnpFilePath)
	cnp := p.fileNameToCnpCache[fileName]
	if cnp == nil {
		return fmt.Errorf("fileNameToCnp map entry doesn't exist for file:%s", fileName)
	}

	resourceID := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindFile,
		p.config.StaticCNPPath,
		fileName,
	)
	p.policyImporter.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:    nil, // delete policy
		Source:   source.Directory,
		Resource: resourceID,
	})

	delete(p.fileNameToCnpCache, fileName)
	return nil
}

func (p *policyWatcher) isValidCNPFileName(filePath string) bool {
	if filepath.Ext(filePath) != ".yaml" {
		return false
	}
	if reasons := validation.IsDNS1123Subdomain(filepath.Base(filePath)); len(reasons) > 0 {
		p.log.Error(
			"CNP name parse validation failed",
			logfields.Name, filepath.Base(filePath),
			logfields.Reasons, reasons,
		)
		return false
	}
	return true
}

func (p *policyWatcher) Wait() {
	p.synced.Wait()
}

func (p *policyWatcher) watchDirectory(ctx context.Context) {
	go func() {
		p.log.Info("Directory policy watcher started")
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logging.Fatal(p.log, "Initializing NewWatcher failed", logfields.Error, err)
			return
		}
		defer watcher.Close()

		dir := p.config.StaticCNPPath
		err = watcher.Add(dir)
		if err != nil {
			logging.Fatal(p.log, "Failed to watch policy directory. Policies will not be loaded from disk",
				logfields.Error, err,
				logfields.Path, dir,
			)
			return
		}

		files, err := os.ReadDir(dir)
		if err != nil {
			logging.Fatal(p.log, "Failed to read policy directory",
				logfields.Error, err,
				logfields.Path, dir,
			)
			return
		}

		// Read existing cnp files before watcher was added
		for _, f := range files {
			absPath := filepath.Join(dir, f.Name())
			if !p.isValidCNPFileName(absPath) {
				continue
			}
			// read from file and convert to cnp object
			cnp, err := p.readAndTranslateToCNPObject(absPath)
			if err != nil {
				logging.Fatal(p.log, "Failed to translate policy yaml file to cnp object",
					logfields.Error, err,
					logfields.Path, absPath,
				)
			} else {

				err = p.addToPolicyEngine(cnp, absPath)
				if err != nil {
					logging.Fatal(p.log, "Failed to add network policy to policy engine",
						logfields.Error, err,
						logfields.Path, absPath,
					)
				}
			}
			reportCNPChangeMetrics(err)
		}
		p.synced.Done()
		// Listen for file add, update, rename and delete
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-watcher.Events:
				if !p.isValidCNPFileName(event.Name) {
					continue
				}
				if event.Op.Has(fsnotify.Create) || event.Op.Has(fsnotify.Write) {
					p.log.Debug("CNP file added/updated in directory..", logfields.Path, event.Name)
					cnp, err := p.readAndTranslateToCNPObject(event.Name)
					if err != nil {
						logging.Fatal(p.log, "Failed to translate policy yaml file to cnp object",
							logfields.Error, err,
							logfields.Path, event.Name,
						)
					} else {
						err = p.addToPolicyEngine(cnp, event.Name)
						if err != nil {
							p.log.Error("Failed to add network policy to policy engine",
								logfields.Error, err,
								logfields.Path, event.Name,
							)
						}
					}
				}
				if event.Op.Has(fsnotify.Remove) || event.Op.Has(fsnotify.Rename) {
					p.log.Debug("CNP file removed from directory..", logfields.Path, event.Name)
					err := p.deleteFromPolicyEngine(event.Name)
					if err != nil {
						p.log.Error("Failed to remove network policy from policy engine",
							logfields.Error, err,
							logfields.Path, event.Name,
						)
					}
				}
				reportCNPChangeMetrics(err)
			case err := <-watcher.Errors:
				p.log.Error("Unexpected error thrown by fsnotify watcher when watching policy directory", logfields.Error, err)
			}
		}
	}()
}

func reportCNPChangeMetrics(err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	}
}
