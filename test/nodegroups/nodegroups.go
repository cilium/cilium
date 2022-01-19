package nodegroups

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/test/helpers"
)

const (
	EksCliCmd = "eksctl"
)

type NodePool struct {
	Name          string
	ClusterName   string
	InstanceTypes []string
	Region        string
	// Number of nodes for fixed size node pools
	NumNodes int
	// Min number of nodes in the nodepool
	MinNodes int
	// Taint to be added to the nodes created in this nodepool
	NodeTaint string
	Executor  *helpers.LocalExecutor
	Kubectl   *helpers.Kubectl
}

type EksNodegroup struct {
	NodePool
}

type NodePoolImpl interface {
	CreateNodePool() error
	DeleteNodePool() error
	ScaleNodePool() error
}

func (e *EksNodegroup) CreateNodePool() error {
	configFile := e.Name + ".yaml"
	tmpl := helpers.ManifestGet(e.Kubectl.BasePath(), "eks-nodegroup.yaml.tmpl")
	err := helpers.RenderTemplateWithData(tmpl, configFile, e.NodePool)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("%s create nodegroup --config-file=%s", EksCliCmd, configFile)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res := e.Executor.ExecContext(ctx, cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to create eks nodegroup : %s", res.OutputPrettyPrint())
	}
	return nil
}

func (e *EksNodegroup) DeleteNodePool() error {
	cmd := fmt.Sprintf("%s delete nodegroup --cluster=%s -n=%s", EksCliCmd, e.ClusterName, e.Name)
	res := e.Executor.ExecMiddle(cmd)
	if !res.WasSuccessful() {
		return fmt.Errorf("unable to create eks nodegroup : %s", res.OutputPrettyPrint())
	}
	return nil
}

func (e *EksNodegroup) ScaleNodePool() error {
	return fmt.Errorf("scaling nodegroup is not implemented yet")
}
