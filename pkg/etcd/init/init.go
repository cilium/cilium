package init

import (
	"context"
	"fmt"

	"go.etcd.io/etcd/client/v3"
)

const (
	rootRoleName = "root"
)

func InitEtcd(ctx context.Context, client *clientv3.Client, clusterName string) error {
	_, err := client.Put(ctx, "cilium/.has-cluster-config", "true")
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
	rootUsername := "root"
	_, err := client.UserAddWithOptions(ctx, rootUsername, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, rootUsername, rootRoleName)
	if err != nil {
		return err
	}
	return nil
}

func setupAdminUser(ctx context.Context, client *clientv3.Client, clusterName string) error {
	adminUsername := fmt.Sprintf("admin-%s", clusterName)
	_, err := client.UserAddWithOptions(ctx, adminUsername, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, adminUsername, rootRoleName)
	if err != nil {
		return err
	}
	return nil
}

func setupExternalWorkloadUser(ctx context.Context, client *clientv3.Client) error {
	externalWorkloadUsername := "externalworkload"
	externalWorkloadRoleName := "externalworkload"
	_, err := client.UserAddWithOptions(ctx, externalWorkloadUsername, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.RoleAdd(ctx, externalWorkloadRoleName)
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, externalWorkloadUsername, externalWorkloadRoleName)
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, externalWorkloadRoleName, "[", "", clientv3.PermissionType(clientv3.PermRead))
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, externalWorkloadRoleName, "cilium/state/noderegister/v1/", "cilium/state/noderegister/v10", clientv3.PermissionType(clientv3.PermReadWrite))
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, externalWorkloadRoleName, "cilium/.initlock/", "cilium/.initlock0", clientv3.PermissionType(clientv3.PermReadWrite))
	if err != nil {
		return err
	}

	return nil
}

func setupRemoteUser(ctx context.Context, client *clientv3.Client) error {
	remoteUsername := "remote"
	remoteRoleName := "remote"
	_, err := client.UserAddWithOptions(ctx, remoteUsername, "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return err
	}
	_, err = client.RoleAdd(ctx, remoteRoleName)
	if err != nil {
		return err
	}
	_, err = client.UserGrantRole(ctx, remoteUsername, remoteRoleName)
	if err != nil {
		return err
	}
	_, err = client.RoleGrantPermission(ctx, remoteRoleName, "[", "", clientv3.PermissionType(clientv3.PermRead))
	if err != nil {
		return err
	}

	return nil
}
