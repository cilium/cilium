package init

import (
	"context"
	"fmt"

	"go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/etcd/init/defaults"
)

func InitEtcd(ctx context.Context, client *clientv3.Client, clusterName string) error {
	_, err := client.Put(ctx, defaults.KeyHasClusterConfig, "true")
	if err != nil {
		return err
	}
	err = setupRootUser(ctx, client)
	if err != nil {
		return err
	}
	err = setupAdminUser(ctx, client, clusterName)
	if err != nil {
		return err
	}
	err = setupExternalWorkloadUser(ctx, client)
	if err != nil {
		return err
	}
	err = setupRemoteUser(ctx, client)
	if err != nil {
		return err
	}
	_, err = client.AuthEnable(ctx)
	if err != nil {
		return err
	}

	return nil
}

func setupRootUser(ctx context.Context, client *clientv3.Client) error {
	_, err := client.UserAddWithOptions(ctx, defaults.RootUserName, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, defaults.RootUserName, defaults.RootRoleName)
	if err != nil {
		return err
	}
	return nil
}

func setupAdminUser(ctx context.Context, client *clientv3.Client, clusterName string) error {
	adminUsername := fmt.Sprintf(defaults.AdminUsernamePrefix, clusterName)
	_, err := client.UserAddWithOptions(ctx, adminUsername, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, adminUsername, defaults.RootRoleName)
	if err != nil {
		return err
	}
	return nil
}

func setupExternalWorkloadUser(ctx context.Context, client *clientv3.Client) error {
	_, err := client.UserAddWithOptions(ctx, defaults.ExternalWorkloadUserName, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.RoleAdd(ctx, defaults.ExternalWorkloadRoleName)
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, defaults.ExternalWorkloadUserName, defaults.ExternalWorkloadRoleName)
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, defaults.ExternalWorkloadRoleName, "[", "", clientv3.PermissionType(clientv3.PermRead))
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, defaults.ExternalWorkloadRoleName, "cilium/state/noderegister/v1/", "cilium/state/noderegister/v10", clientv3.PermissionType(clientv3.PermReadWrite))
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, defaults.ExternalWorkloadRoleName, "cilium/.initlock/", "cilium/.initlock0", clientv3.PermissionType(clientv3.PermReadWrite))
	if err != nil {
		return err
	}

	return nil
}

func setupRemoteUser(ctx context.Context, client *clientv3.Client) error {
	_, err := client.UserAddWithOptions(ctx, defaults.RemoteUserName, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.RoleAdd(ctx, defaults.RemoteRoleName)
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, defaults.RemoteUserName, defaults.RemoteRoleName)
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, defaults.RemoteRoleName, "[", "", clientv3.PermissionType(clientv3.PermRead))
	if err != nil {
		return err
	}

	return nil
}
