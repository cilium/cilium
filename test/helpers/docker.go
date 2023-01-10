// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"
	"strings"

	"github.com/onsi/ginkgo"

	"github.com/cilium/cilium/test/helpers/constants"
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

// ContainerRun is a wrapper to a one execution docker run container. It runs
// an instance of the specific Docker image with the provided network, name and
// options.
func (s *SSHMeta) ContainerRun(name, image, net, options string, cmdParams ...string) *CmdRes {
	cmdOnStart := ""
	if len(cmdParams) > 0 {
		cmdOnStart = strings.Join(cmdParams, " ")
	}
	cmd := fmt.Sprintf(
		"docker run --name %s --net %s %s %s %s", name, net, options, image, cmdOnStart)
	return s.ExecWithSudo(cmd)
}

// ContainerCreate is a wrapper for `docker run`. It runs an instance of the
// specified Docker image with the provided network, name, options and container
// startup commands.
func (s *SSHMeta) ContainerCreate(name, image, net, options string, cmdParams ...string) *CmdRes {
	cmdOnStart := ""
	if len(cmdParams) > 0 {
		cmdOnStart = strings.Join(cmdParams, " ")
	}
	if _, ok := constants.AllImages[image]; !ok {
		ginkgo.Fail(fmt.Sprintf("Image %s is not in the set of pre-pulled Docker images; add this image to `AllImages` in `test/helpers/constants/images.go` and / or update the VM image to pull this image if necessary", image), 1)
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

func (s *SSHMeta) containerInspectNet(name string, network string) (map[string]string, error) {
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
	filter := fmt.Sprintf(`{ [0].NetworkSettings.Networks.%s }`, network)
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

// ContainerInspectOtherNet returns a map of Docker networking information
// fields and their associated values for the container of the provided name,
// on the specified docker network. An error is returned if the networking
// information could not be retrieved.
func (s *SSHMeta) ContainerInspectOtherNet(name string, network string) (map[string]string, error) {
	return s.containerInspectNet(name, network)
}

// ContainerInspectNet returns a map of Docker networking information fields and
// their associated values for the container of the provided name. An error
// is returned if the networking information could not be retrieved.
func (s *SSHMeta) ContainerInspectNet(name string) (map[string]string, error) {
	return s.containerInspectNet(name, CiliumDockerNetwork)
}

// NetworkCreateWithOptions creates a Docker network of the provided name with
// the specified subnet, with custom specified options. It is a wrapper around
// `docker network create`.
func (s *SSHMeta) NetworkCreateWithOptions(name string, subnet string, ipv6 bool, opts string) *CmdRes {
	ipv6Arg := ""
	if ipv6 {
		ipv6Arg = "--ipv6"
	}
	cmd := fmt.Sprintf(
		"docker network create %s --subnet %s %s %s",
		ipv6Arg, subnet, opts, name)
	res := s.ExecWithSudo(cmd)
	if !res.WasSuccessful() {
		s.logger.Warningf("Unable to create docker network %s: %s", name, res.CombineOutput().String())
	}

	return res
}

// NetworkCreate creates a Docker network of the provided name with the
// specified subnet. It is a wrapper around `docker network create`.
func (s *SSHMeta) NetworkCreate(name string, subnet string) *CmdRes {
	if subnet == "" {
		subnet = "::1/112"
	}
	return s.NetworkCreateWithOptions(name, subnet, true,
		"--driver cilium --ipam-driver cilium")
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

// SampleContainersActions creates or deletes various containers used for
// testing Cilium and adds said containers to the provided Docker network.
func (s *SSHMeta) SampleContainersActions(mode string, networkName string, createOptions ...string) {
	createOptionsString := ""
	for _, opt := range createOptions {
		createOptionsString = fmt.Sprintf("%s %s", createOptionsString, opt)
	}

	images := map[string]string{
		Httpd1: constants.HttpdImage,
		Httpd2: constants.HttpdImage,
		Httpd3: constants.HttpdImage,
		App1:   constants.NetperfImage,
		App2:   constants.NetperfImage,
		App3:   constants.NetperfImage,
	}

	switch mode {
	case Create:
		for k, v := range images {
			res := s.ContainerCreate(k, v, networkName, fmt.Sprintf("-l id.%s %s", k, createOptionsString))
			res.ExpectSuccess("failed to create container %s", k)
		}
		s.WaitEndpointsReady()
	case Delete:
		for k := range images {
			s.ContainerRm(k)
		}
		s.WaitEndpointsDeleted()
	}
}

// GatherDockerLogs dumps docker containers logs output to the directory
// testResultsPath
func (s *SSHMeta) GatherDockerLogs() {
	res := s.Exec("docker ps -a --format {{.Names}}")
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
