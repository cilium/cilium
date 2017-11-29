// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"bytes"
	"fmt"
)

// Docker is utilized to run docker-specific commands on its SSHMeta. Informational
// output about the result of commands and the state of the node is stored in its
// associated logCxt.
type Docker struct {
	Node *SSHMeta

	logCxt *log.Entry
}

// CreateDocker returns a Docker object containing the SSHMeta of the provided vmName,
// as well as the provided logger.
// TODO - I don't understand why we need separate Cilium vs. Docker constructs.
// The contents are exactly the same. Why not just declare a single type that we name
// accordingly?
func CreateDocker(target string, log *log.Entry) *Docker {
	log.Infof("Docker: set target to '%s'", target)
	node := GetVagrantSSHMetadata(target)
	if node == nil {
		return nil
	}

	return &Docker{
		Node:   node,
		logCxt: log,
	}
}

// ContainerExec executes cmd in the container with the provided name.
func (do *Docker) ContainerExec(name string, cmd string) *CmdRes {
	return do.execCmd(fmt.Sprintf("docker exec -i %s %s", name, cmd))
}

// ContainerCreate is a wrapper for `docker run`. It runs an instance of the
// specified Docker image with the provided network, name, and options.
func (do *Docker) ContainerCreate(name, image, net, options string) *CmdRes {
	cmd := fmt.Sprintf(
		"docker run -d --name %s --net %s %s %s", name, net, options, image)
	log.Debugf("spinning up container with command %q", cmd)
	return do.execCmd(cmd)
}

// ContainerRm is a wrapper around `docker rm -f`. It forcibly removes the
// Docker container of the provided name.
func (do *Docker) ContainerRm(name string) *CmdRes {
	return do.execCmd(fmt.Sprintf("docker rm -f %s", name))
}

// ContainerInspect runs `docker inspect` for the container with the provided
// name.
func (do *Docker) ContainerInspect(name string) *CmdRes {
	return do.execCmd(fmt.Sprintf("docker inspect %s", name))
}

// ContainerInspectNet returns a map of Docker networking information fields and
// their associated values for the container of the provided name. An error
// is returned if the networking information could not be retrieved.
func (do *Docker) ContainerInspectNet(name string) (map[string]string, error) {
	res := do.ContainerInspect(name)
	properties := map[string]string{
		"EndpointID":        "EndpointID",
		"GlobalIPv6Address": IPv6,
		"IPAddress":         IPv4,
		"NetworkID":         "NetworkID",
	}

	if !res.WasSuccessful() {
		return nil, fmt.Errorf("could not inspect container %s", name)
	}
	filter := fmt.Sprintf(`{ [0].NetworkSettings.Networks.%s }`, CiliumDockerNetwork)
	result := make(map[string]string)
	data, err := res.FindResults(filter)
	if err != nil {
		return nil, err
	}
	for _, val := range data {
		iface := val.Interface()
		for k, v := range iface.(map[string]interface{}) {
			if key, ok := properties[k]; ok {
				result[key] = fmt.Sprintf("%s", v)
			}
		}
	}
	return result, nil
}

// NetworkCreate creates a Docker network of the provided name with the
// specified subnet. It is a wrapper around `docker network create`.
func (do *Docker) NetworkCreate(name string, subnet string) *CmdRes {
	if subnet == "" {
		subnet = "::1/112"
	}
	cmd := fmt.Sprintf(
		"docker network create --ipv6 --subnet %s --driver cilium --ipam-driver cilium %s",
		subnet, name)
	return do.execCmd(cmd)
}

// NetworkDelete deletes the Docker network of the provided name. It is a wrapper
// around `docker network rm`.
func (do *Docker) NetworkDelete(name string) *CmdRes {
	return do.execCmd(fmt.Sprintf("docker network rm  %s", name))
}

// NetworkGet returns all of the Docker network configuration for the provided
// network. It is a wrapper around `docker network inspect`.
func (do *Docker) NetworkGet(name string) *CmdRes {
	return do.execCmd(fmt.Sprintf("docker network inspect %s", name))
}

func (do *Docker) execCmd(cmd string) *CmdRes {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	exit := do.Node.ExecWithSudo(cmd, stdout, stderr)
	return &CmdRes{
		cmd:    cmd,
		stdout: stdout,
		stderr: stderr,
		exit:   exit,
	}
}

// SampleContainersActions creates or deletes various containers used for
// testing Cilium and adds said containers to the provided Docker network.
func (do *Docker) SampleContainersActions(mode string, networkName string) {
	images := map[string]string{
		Httpd1: HttpdImage,
		Httpd2: HttpdImage,
		Httpd3: HttpdImage,
		App1:   NetperfImage,
		App2:   NetperfImage,
		App3:   NetperfImage,
	}

	switch mode {
	case Create:
		for k, v := range images {
			do.ContainerCreate(k, v, networkName, fmt.Sprintf("-l id.%s", k))
		}
	case Delete:
		for k := range images {
			do.ContainerRm(k)
		}
	}
}
