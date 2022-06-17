/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kind

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	log "k8s.io/klog/v2"

	"github.com/vladimirvivien/gexe"
)

var kindVersion = "v0.12.0"

type Cluster struct {
	name        string
	e           *gexe.Echo
	kubecfgFile string
	version     string
}

func NewCluster(name string) *Cluster {
	return &Cluster{name: name, e: gexe.New()}
}

// WithVersion set kind version
func (k *Cluster) WithVersion(ver string) *Cluster {
	k.version = ver
	return k
}

func (k *Cluster) getKubeconfig() (string, error) {
	kubecfg := fmt.Sprintf("%s-kubecfg", k.name)

	p := k.e.StartProc(fmt.Sprintf(`kind get kubeconfig --name %s`, k.name))
	if p.Err() != nil {
		return "", fmt.Errorf("kind get kubeconfig: %w", p.Err())
	}
	var stdout bytes.Buffer
	if _, err := stdout.ReadFrom(p.StdOut()); err != nil {
		return "", fmt.Errorf("kind kubeconfig stdout bytes: %w", err)
	}
	if p.Wait().Err() != nil {
		return "", fmt.Errorf("kind get kubeconfig: %s: %w", p.Result(), p.Err())
	}

	file, err := ioutil.TempFile("", fmt.Sprintf("kind-cluser-%s", kubecfg))
	if err != nil {
		return "", fmt.Errorf("kind kubeconfig file: %w", err)
	}
	defer file.Close()

	k.kubecfgFile = file.Name()

	if n, err := io.Copy(file, &stdout); n == 0 || err != nil {
		return "", fmt.Errorf("kind kubecfg file: bytes copied: %d: %w]", n, err)
	}

	return file.Name(), nil
}

func (k *Cluster) clusterExists(name string) (string, bool) {
	clusters := k.e.Run("kind get clusters")
	for _, c := range strings.Split(clusters, "\n") {
		if c == name {
			return clusters, true
		}
	}
	return clusters, false
}

func (k *Cluster) CreateWithConfig(imageName, kindConfigFile string) (string, error) {
	return k.Create("--image", imageName, "--config", kindConfigFile)
}

func (k *Cluster) Create(args ...string) (string, error) {
	log.V(4).Info("Creating kind cluster ", k.name)
	if err := k.findOrInstallKind(k.e); err != nil {
		return "", err
	}

	if _, ok := k.clusterExists(k.name); ok {
		log.V(4).Info("Skipping Kind Cluster.Create: cluster already created: ", k.name)
		return k.getKubeconfig()
	}

	command := fmt.Sprintf(`kind create cluster --name %s`, k.name)
	if len(args) > 0 {
		command = fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	}
	log.V(4).Info("Launching:", command)
	p := k.e.RunProc(command)
	if p.Err() != nil {
		return "", fmt.Errorf("failed to create kind cluster: %s : %s", p.Err(), p.Result())
	}

	clusters, ok := k.clusterExists(k.name)
	if !ok {
		return "", fmt.Errorf("kind Cluster.Create: cluster %v still not in 'cluster list' after creation: %v", k.name, clusters)
	}
	log.V(4).Info("kind clusters available: ", clusters)

	// Grab kubeconfig file for cluster.
	return k.getKubeconfig()
}

// GetKubeconfig returns the path of the kubeconfig file
// associated with this kind cluster
func (k *Cluster) GetKubeconfig() string {
	return k.kubecfgFile
}

func (k *Cluster) GetKubeCtlContext() string {
	return fmt.Sprintf("kind-%s", k.name)
}

func (k *Cluster) Destroy() error {
	log.V(4).Info("Destroying kind cluster ", k.name)
	if err := k.findOrInstallKind(k.e); err != nil {
		return err
	}

	p := k.e.RunProc(fmt.Sprintf(`kind delete cluster --name %s`, k.name))
	if p.Err() != nil {
		return fmt.Errorf("kind: delete cluster failed: %s: %s", p.Err(), p.Result())
	}

	log.V(4).Info("Removing kubeconfig file ", k.kubecfgFile)
	if err := os.RemoveAll(k.kubecfgFile); err != nil {
		return fmt.Errorf("kind: remove kubefconfig failed: %w", err)
	}

	return nil
}

func (k *Cluster) findOrInstallKind(e *gexe.Echo) error {
	if e.Prog().Avail("kind") == "" {
		log.V(4).Infof(`kind not found, installing with go install sigs.k8s.io/kind@%s`, kindVersion)
		if err := k.installKind(e); err != nil {
			return err
		}
	}
	return nil
}

func (k *Cluster) installKind(e *gexe.Echo) error {
	if k.version != "" {
		kindVersion = k.version
	}

	log.V(4).Infof("Installing: go install sigs.k8s.io/kind@%s", kindVersion)
	p := e.RunProc(fmt.Sprintf("go install sigs.k8s.io/kind@%s", kindVersion))
	if p.Err() != nil {
		return fmt.Errorf("failed to install kind: %s", p.Err())
	}

	if !p.IsSuccess() || p.ExitCode() != 0 {
		return fmt.Errorf("failed to install kind: %s", p.Result())
	}

	// PATH may already be set to include $GOPATH/bin so we don't need to.
	if kindPath := e.Prog().Avail("kind"); kindPath != "" {
		log.V(4).Info("Installed kind at", kindPath)
		return nil
	}

	p = e.RunProc("ls $GOPATH/bin")
	if p.Err() != nil {
		return fmt.Errorf("failed to install kind: %s", p.Err())
	}

	p = e.RunProc("echo $PATH:$GOPATH/bin")
	if p.Err() != nil {
		return fmt.Errorf("failed to install kind: %s", p.Err())
	}

	log.V(4).Info(`Setting path to include $GOPATH/bin:`, p.Result())
	e.SetEnv("PATH", p.Result())

	if kindPath := e.Prog().Avail("kind"); kindPath != "" {
		log.V(4).Info("Installed kind at", kindPath)
		return nil
	}
	return fmt.Errorf("kind not available even after installation")
}

// LoadDockerImage loads a docker image from the host into the kind cluster
func (k *Cluster) LoadDockerImage(image string) error {
	p := k.e.RunProc(fmt.Sprintf(`kind load docker-image --name %s %s`, k.name, image))
	if p.Err() != nil {
		return fmt.Errorf("kind: load docker-image failed: %s: %s", p.Err(), p.Result())
	}
	return nil
}

// LoadImageArchive loads a docker image TAR archive from the host into the kind cluster
func (k *Cluster) LoadImageArchive(imageArchive string) error {
	p := k.e.RunProc(fmt.Sprintf(`kind load image-archive --name %s %s`, k.name, imageArchive))
	if p.Err() != nil {
		return fmt.Errorf("kind: load image-archive failed: %s: %s", p.Err(), p.Result())
	}
	return nil
}
