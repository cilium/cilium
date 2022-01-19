package helpers

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/test/config"
)

const (
	CiliumCliCmd = "cilium"
)

type CiliumCli struct {
	executor Executor
	log      *logrus.Entry
}

func CreateCiliumCli(log *logrus.Entry) (c *CiliumCli) {
	var environ []string
	if config.CiliumTestConfig.PassCLIEnvironment {
		environ = append(environ, os.Environ()...)
	}
	environ = append(environ, "KUBECONFIG="+config.CiliumTestConfig.Kubeconfig)
	environ = append(environ, fmt.Sprintf("PATH=%s:%s", GetKubectlPath(), os.Getenv("PATH")))

	c = &CiliumCli{
		executor: CreateLocalExecutor(environ),
		log:      log,
	}
	return c
}

func (c *CiliumCli) UpdateCiliumConfig(key string, val string, restart bool) error {
	res := c.executor.ExecShort(fmt.Sprintf("%s config set --restart=%v %s %s", CiliumCliCmd, restart, key, val))

	if !res.WasSuccessful() {
		return fmt.Errorf("unable to update config with error %s", res.OutputPrettyPrint())
	}
	return nil
}
