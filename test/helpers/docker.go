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
	"fmt"
	"strings"
)

// ContainerExec executes cmd in the container with the provided name along with
// any other additional arguments needed.
func (s *SSHMeta) ContainerExec(name string, cmd string, optionalArgs ...string) *CmdRes {
	optionalArgsCoalesced := ""
	if len(optionalArgs) > 0 {
		optionalArgsCoalesced = strings.Join(optionalArgs, " ")
	}
	dockerCmd := fmt.Sprintf("docker exec -i %s %s %s", optionalArgsCoalesced, name, cmd)
	return s.Exec(dockerCmd)
}

// ContainerCreate is a wrapper for `docker run`. It runs an instance of the
// specified Docker image with the provided network, name, options and container
// startup commands.
func (s *SSHMeta) ContainerCreate(name, image, net, options string, cmdParams ...string) *CmdRes {
	cmdOnStart := ""
	if len(cmdParams) > 0 {
		cmdOnStart = strings.Join(cmdParams, " ")
	}
	cmd := fmt.Sprintf(
		"docker run -d --name %s --net %s %s %s %s", name, net, options, image, cmdOnStart)
	log.Debugf("spinning up container with command '%v'", cmd)
	return s.ExecWithSudo(cmd)
}

// ContainerRm is a wrapper around `docker rm -f`. It forcibly removes the
// Docker container of the provided name.
func (s *SSHMeta) ContainerRm(name string) *CmdRes {
	cmd := fmt.Sprintf("docker rm -f %s", name)
	return s.ExecWithSudo(cmd)
}

// ContainerInspect runs `docker inspect` for the container with the provided
// name.
func (s *SSHMeta) ContainerInspect(name string) *CmdRes {
	return s.ExecWithSudo(fmt.Sprintf("docker inspect %s", name))
}

// ContainerInspectNet returns a map of Docker networking information fields and
// their associated values for the container of the provided name. An error
// is returned if the networking information could not be retrieved.
func (s *SSHMeta) ContainerInspectNet(name string) (map[string]string, error) {
	res := s.ContainerInspect(name)
	properties := map[string]string{
		"EndpointID":        "EndpointID",
		"GlobalIPv6Address": IPv6,
		"IPAddress":         IPv4,
		"NetworkID":         "NetworkID",
		"IPv6Gateway":       "IPv6Gateway",
	}

	if !res.WasSuccessful() {
		return nil, fmt.Errorf("could not inspect container %s", name)
	}
	filter := fmt.Sprintf(`{ [0].NetworkSettings.Networks.%s }`, CiliumDockerNetwork)
	result := map[string]string{
		Name: name,
	}
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
func (s *SSHMeta) NetworkCreate(name string, subnet string) *CmdRes {
	if subnet == "" {
		subnet = "::1/112"
	}
	cmd := fmt.Sprintf(
		"docker network create --ipv6 --subnet %s --driver cilium --ipam-driver cilium %s",
		subnet, name)
	return s.ExecWithSudo(cmd)
}

// NetworkDelete deletes the Docker network of the provided name. It is a wrapper
// around `docker network rm`.
func (s *SSHMeta) NetworkDelete(name string) *CmdRes {
	return s.ExecWithSudo(fmt.Sprintf("docker network rm  %s", name))
}

// NetworkGet returns all of the Docker network configuration for the provided
// network. It is a wrapper around `docker network inspect`.
func (s *SSHMeta) NetworkGet(name string) *CmdRes {
	return s.ExecWithSudo(fmt.Sprintf("docker network inspect %s", name))
}

func (s *SSHMeta) execCmd(cmd string) *CmdRes {
	return s.ExecWithSudo(cmd)
}

// SampleContainersActions creates or deletes various containers used for
// testing Cilium and adds said containers to the provided Docker network.
func (s *SSHMeta) SampleContainersActions(mode string, networkName string, createOptions ...string) {
	createOptionsString := ""
	for _, opt := range createOptions {
		createOptionsString = fmt.Sprintf("%s %s", createOptionsString, opt)
	}

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
			s.ContainerCreate(k, v, networkName, fmt.Sprintf("-l id.%s %s", k, createOptionsString))
		}
	case Delete:
		for k := range images {
			s.ContainerRm(k)
		}
	}
}

// GatherDockerLogs dumps docker containers logs output to the directory
// testResultsPath
func (s *SSHMeta) GatherDockerLogs() {
	res := s.Exec("docker ps -aq")
	if !res.WasSuccessful() {
		log.WithField("error", res.CombineOutput()).Errorf("cannot get docker logs")
		return
	}
	commands := map[string]string{}
	for _, k := range res.ByLines() {
		if k != "" {
			key := fmt.Sprintf("docker logs %s", k)
			commands[key] = fmt.Sprintf("container_%s.log", k)
		}
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, commands, s)
}
