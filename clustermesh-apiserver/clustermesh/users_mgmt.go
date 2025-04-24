// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/fswatcher"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	usersMgmtCtrl = "clustermesh-users-management"
)

var usersManagementCell = cell.Module(
	"clustermesh-users-management",
	"ClusterMesh Etcd Users Management",

	kvstore.GlobalUserMgmtClientPromiseCell,
	cell.Config(UsersManagementConfig{}),
	cell.Invoke(registerUsersManager),
)

var usersManagementControllerGroup = controller.NewGroup("clustermesh-users-management")

type UsersManagementConfig struct {
	ClusterUsersEnabled    bool
	ClusterUsersConfigPath string
}

func (UsersManagementConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("cluster-users-enabled", false,
		"Enable the management of etcd users for remote clusters")
	flags.String("cluster-users-config-path", "/var/lib/cilium/etcd-config/users.yaml",
		"The path of the config file with the list of remote cluster users")
}

type usersConfigFile struct {
	Users []struct {
		Name string `yaml:"name"`
		Role string `yaml:"role"`
	} `yaml:"users"`
}

type usersManager struct {
	UsersManagementConfig
	clusterInfo cmtypes.ClusterInfo

	client        kvstore.BackendOperationsUserMgmt
	clientPromise promise.Promise[kvstore.BackendOperationsUserMgmt]

	manager *controller.Manager
	users   map[string]string

	stop   chan struct{}
	wg     sync.WaitGroup
	logger *slog.Logger
}

func registerUsersManager(
	lc cell.Lifecycle,
	cfg UsersManagementConfig,
	cinfo cmtypes.ClusterInfo,
	clientPromise promise.Promise[kvstore.BackendOperationsUserMgmt],
	logger *slog.Logger,
) error {
	if !cfg.ClusterUsersEnabled {
		logger.Info("etcd users management disabled")
		return nil
	}

	manager := usersManager{
		UsersManagementConfig: cfg,
		clientPromise:         clientPromise,

		manager: controller.NewManager(),
		users:   make(map[string]string),

		stop: make(chan struct{}),

		logger: logger,
	}

	lc.Append(&manager)
	return nil
}

func (us *usersManager) Start(cell.HookContext) error {
	us.logger.Info(
		"Starting managing etcd users based on configuration",
		logfields.Path, us.ClusterUsersConfigPath,
	)

	configWatcher, err := fswatcher.New(us.logger, []string{us.ClusterUsersConfigPath})
	if err != nil {
		us.logger.Error("Unable to setup config watcher", logfields.Error, err)
		return fmt.Errorf("unable to setup config watcher: %w", err)
	}

	us.manager.UpdateController(usersMgmtCtrl, controller.ControllerParams{
		Group:   usersManagementControllerGroup,
		Context: context.Background(),
		DoFunc:  us.sync,
	})

	us.wg.Add(1)
	go func() {
		defer us.wg.Done()

		for {
			select {
			case <-configWatcher.Events:
				us.manager.TriggerController(usersMgmtCtrl)
			case err := <-configWatcher.Errors:
				us.logger.Warn(
					"Error encountered while watching file with fsnotify",
					logfields.Error, err,
					logfields.Path, us.ClusterUsersConfigPath,
				)
			case <-us.stop:
				us.logger.Info("Closing")
				configWatcher.Close()
				return
			}
		}
	}()

	return nil
}

func (us *usersManager) Stop(cell.HookContext) error {
	us.logger.Info(
		"Stopping managing etcd users based on configuration",
		logfields.Path, us.ClusterUsersConfigPath,
	)

	us.manager.RemoveAllAndWait()
	close(us.stop)
	us.wg.Wait()
	return nil
}

func (us *usersManager) sync(ctx context.Context) error {
	if us.client == nil {
		client, err := us.clientPromise.Await(ctx)
		if err != nil {
			us.logger.Error("Unable to retrieve the kvstore client", logfields.Error, err)
			return err
		}
		us.client = client
	}

	config, err := os.ReadFile(us.ClusterUsersConfigPath)
	if err != nil {
		us.logger.Error(
			"Failed reading users configuration file",
			logfields.Error, err,
			logfields.Path, us.ClusterUsersConfigPath,
		)
		return err
	}

	var users usersConfigFile
	if err := yaml.Unmarshal(config, &users); err != nil {
		us.logger.Error(
			"Failed un-marshalling users configuration file",
			logfields.Error, err,
			logfields.Path, us.ClusterUsersConfigPath,
		)
		return err
	}

	// Mark all users as stale
	stale := make(map[string]struct{}, len(us.users))
	for user := range us.users {
		stale[user] = struct{}{}
	}

	for _, user := range users.Users {
		if user.Name == us.clusterInfo.Name {
			continue
		}

		role, found := us.users[user.Name]
		if !found || role != user.Role {
			if err := us.client.UserEnforcePresence(ctx, user.Name, []string{user.Role}); err != nil {
				us.logger.Error(
					"Failed configuring user",
					logfields.Error, err,
					logfields.User, user.Name,
				)
				return err
			}

			us.logger.Info("User successfully configured", logfields.User, user.Name)
		}

		us.users[user.Name] = user.Role
		delete(stale, user.Name)
	}

	// Delete all stale users
	for user := range stale {
		if err := us.client.UserEnforceAbsence(ctx, user); err != nil {
			us.logger.Error(
				"Failed removing user",
				logfields.Error, err,
				logfields.User, user,
			)
			return err
		}

		us.logger.Info("User successfully removed", logfields.User, user)
		delete(us.users, user)
	}

	return nil
}
