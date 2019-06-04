// Copyright 2017-2019 Authors of Cilium
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
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/kevinburke/ssh_config"
	"github.com/onsi/ginkgo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHCommand stores the data associated with executing a command.
// TODO: this is poorly named in that it's not related to a command only
// ran over SSH - rename this.
type SSHCommand struct {
	// TODO: path is not a clear name - rename to something more clear.
	Path   string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// SSHClient stores the information needed to SSH into a remote location for
// running tests.
type SSHClient struct {
	Config *ssh.ClientConfig // ssh client configuration information.
	Host   string            // Ip/Host from the target virtualserver
	Port   int               // Port to connect to the target server
	client *ssh.Client       // Client implements a traditional SSH client that supports shells,
	// subprocesses, TCP port/streamlocal forwarding and tunneled dialing.
}

// GetHostPort returns the host port representation of the ssh client
func (cli *SSHClient) GetHostPort() string {
	return net.JoinHostPort(cli.Host, strconv.Itoa(cli.Port))
}

// SSHConfig contains metadata for an SSH session.
type SSHConfig struct {
	target       string
	host         string
	user         string
	port         int
	identityFile string
}

// SSHConfigs maps the name of a host (VM) to its corresponding SSHConfiguration
type SSHConfigs map[string]*SSHConfig

// GetSSHClient initializes an SSHClient based on the provided SSHConfig
func (cfg *SSHConfig) GetSSHClient() *SSHClient {
	sshConfig := &ssh.ClientConfig{
		User: cfg.user,
		Auth: []ssh.AuthMethod{
			cfg.GetSSHAgent(),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	return &SSHClient{
		Config: sshConfig,
		Host:   cfg.host,
		Port:   cfg.port,
	}
}

func (client *SSHClient) String() string {
	return fmt.Sprintf("host: %s, port: %d, user: %s", client.Host, client.Port, client.Config.User)
}

func (cfg *SSHConfig) String() string {
	return fmt.Sprintf("target: %s, host: %s, port %d, user, %s, identityFile: %s", cfg.target, cfg.host, cfg.port, cfg.user, cfg.identityFile)
}

// GetSSHAgent returns the ssh.AuthMethod corresponding to SSHConfig cfg.
func (cfg *SSHConfig) GetSSHAgent() ssh.AuthMethod {
	key, err := ioutil.ReadFile(cfg.identityFile)
	if err != nil {
		log.Fatalf("unable to retrieve ssh-key on target '%s': %s", cfg.target, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key on target '%s': %s", cfg.target, err)
	}
	return ssh.PublicKeys(signer)
}

// ImportSSHconfig imports the SSH configuration stored at the provided path.
// Returns an error if the SSH configuration could not be instantiated.
func ImportSSHconfig(config []byte) (SSHConfigs, error) {
	result := make(SSHConfigs)
	cfg, err := ssh_config.Decode(bytes.NewBuffer(config))
	if err != nil {
		return nil, err
	}

	for _, host := range cfg.Hosts {
		key := host.Patterns[0].String()
		if key == "*" {
			continue
		}
		port, _ := cfg.Get(key, "Port")
		hostConfig := SSHConfig{target: key}
		hostConfig.host, _ = cfg.Get(key, "Hostname")
		hostConfig.identityFile, _ = cfg.Get(key, "identityFile")
		hostConfig.user, _ = cfg.Get(key, "User")
		hostConfig.port, _ = strconv.Atoi(port)
		result[key] = &hostConfig
	}
	return result, nil
}

// copyWait runs an instance of io.Copy() in a goroutine, and returns a channel
// to receive the error result.
func copyWait(dst io.Writer, src io.Reader) chan error {
	c := make(chan error, 1)
	go func() {
		_, err := io.Copy(dst, src)
		c <- err
	}()
	return c
}

// runCommand runs the specified command on the provided SSH session, and
// gathers both of the sterr and stdout output into the writers provided by
// cmd. Returns whether the command was run and an optional error.
// Returns nil when the command completes successfully and all stderr,
// stdout output has been written. Returns an error otherwise.
func runCommand(session *ssh.Session, cmd *SSHCommand) (bool, error) {
	stderr, err := session.StderrPipe()
	if err != nil {
		return false, fmt.Errorf("Unable to setup stderr for session: %v", err)
	}
	errChan := copyWait(cmd.Stderr, stderr)

	stdout, err := session.StdoutPipe()
	if err != nil {
		return false, fmt.Errorf("Unable to setup stdout for session: %v", err)
	}
	outChan := copyWait(cmd.Stdout, stdout)

	if err = session.Run(cmd.Path); err != nil {
		return false, err
	}

	if err = <-errChan; err != nil {
		return true, err
	}
	if err = <-outChan; err != nil {
		return true, err
	}
	return true, nil
}

// RunCommand runs a SSHCommand using SSHClient client. The returned error is
// nil if the command runs, has no problems copying stdin, stdout, and stderr,
// and exits with a zero exit status.
func (client *SSHClient) RunCommand(cmd *SSHCommand) error {
	session, err := client.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	_, err = runCommand(session, cmd)
	return err
}

// RunCommandInBackground runs an SSH command in a similar way to
// RunCommandContext, but with a context which allows the command to be
// cancelled at any time. When cancel is called the error of the command is
// returned instead the context error.
func (client *SSHClient) RunCommandInBackground(ctx context.Context, cmd *SSHCommand) error {
	if ctx == nil {
		panic("nil context provided to RunCommandInBackground()")
	}

	session, err := client.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	session.RequestPty("xterm-256color", 80, 80, modes)

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Errorf("Could not get stdin: %s", err)
	}

	go func() {
		select {
		case <-ctx.Done():
			_, err := stdin.Write([]byte{3})
			if err != nil {
				log.Errorf("write ^C error: %s", err)
			}
			err = session.Wait()
			if err != nil {
				log.Errorf("wait error: %s", err)
			}
			if err = session.Signal(ssh.SIGHUP); err != nil {
				log.Errorf("failed to kill command: %s", err)
			}
			if err = session.Close(); err != nil {
				log.Errorf("failed to close session: %s", err)
			}
		}
	}()
	_, err = runCommand(session, cmd)
	return err
}

// RunCommandContext runs an SSH command in a similar way to RunCommand but with
// a context. If context is canceled it will return the error of that given
// context.
func (client *SSHClient) RunCommandContext(ctx context.Context, cmd *SSHCommand) error {
	if ctx == nil {
		panic("nil context provided to RunCommandContext()")
	}

	session, err := client.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Errorf("Could not get stdin %s", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		select {
		case <-ctx.Done():
			_, err := stdin.Write([]byte{3})
			if err != nil {
				log.Errorf("write ^C error: %s", err)
			}
			err = session.Wait()
			if err != nil {
				log.Errorf("wait error: %s", err)
			}
			if err = session.Signal(ssh.SIGHUP); err != nil {
				log.Errorf("failed to kill command: %s", err)
			}
			if err = session.Close(); err != nil {
				log.Errorf("failed to close session: %s", err)
			}
		}
		wg.Done()
	}()

	running, err := runCommand(session, cmd)
	if !running {
		return err
	}
	select {
	case <-ctx.Done():
		// Wait until the ssh session is stopped
		ginkgo.By("Waiting for SSH session to be stopped")
		wg.Wait()
		return ctx.Err()
	default:
		return err
	}
}

func (client *SSHClient) newSession() (*ssh.Session, error) {
	var connection *ssh.Client
	var err error

	if client.client != nil {
		connection = client.client
	} else {
		connection, err = ssh.Dial(
			"tcp",
			fmt.Sprintf("%s:%d", client.Host, client.Port),
			client.Config)

		if err != nil {
			return nil, fmt.Errorf("failed to dial: %s", err)
		}
		client.client = connection
	}

	session, err := connection.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %s", err)
	}

	return session, nil
}

// SSHAgent returns the ssh.Authmethod using the Public keys. Returns nil if
// a connection to SSH_AUTH_SHOCK does not succeed.
func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

// GetSSHClient initializes an SSHClient for the specified host/port/user
// combination.
func GetSSHClient(host string, port int, user string) *SSHClient {

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			SSHAgent(),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	return &SSHClient{
		Config: sshConfig,
		Host:   host,
		Port:   port,
	}

}
