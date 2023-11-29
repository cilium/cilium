// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package init

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/authpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/node/store"
)

// ClusterMeshEtcdInit initializes etcd for use by Cilium Clustermesh via the provided client. It creates a number of
// user accounts and roles with permissions, sets a well-known key to indicate that clients should expect a cilium
// config to be present, and enables authentication for the cluster.
//
// This function uses log to perform informational and debug logging about operations. This function does not log errors
// and instead returns an error for handling, as it is assumed that the calling function will log errors. Most errors
// are wrapped with extra context as to the situation in which the error arose.
//
// The ciliumClusterName is used to determine the admin username.
//
// The context provided as ctx can be used to implement a timeout on operations, and is passed to all etcd client
// functions.
//
// Note that this function is **not idempotent**. It expects a completely blank etcd server with no non-default users,
// roles, permissions, or keys.
func ClusterMeshEtcdInit(ctx context.Context, log *logrus.Entry, client *clientv3.Client, ciliumClusterName string) error {
	ic := initClient{
		log:    log,
		client: client,
	}

	// This function is largely procedural. The various functions on initClient already perform logging and wrap errors
	// with additional context. So this function only performs the relevant operations, and is more or less a 1:1
	// translation of the shell script that this function replaced.

	// Pre setup
	log.Info("Performing pre-init tasks")
	err := ic.putHasConfigKey(ctx)
	if err != nil {
		return err
	}

	// Root user
	rootUsername := username("root")
	log.WithField("etcdUsername", rootUsername).
		Info("Configuring root user")
	err = ic.addNoPasswordUser(ctx, rootUsername)
	if err != nil {
		return err
	}
	err = ic.grantRoleToUser(ctx, rootRolename, rootUsername)
	if err != nil {
		return err
	}

	// Admin user
	adminUsername := adminUsernameForClusterName(ciliumClusterName)
	log.WithField("etcdUsername", adminUsername).
		Info("Configuring admin user")
	err = ic.addNoPasswordUser(ctx, adminUsername)
	if err != nil {
		return err
	}
	err = ic.grantRoleToUser(ctx, rootRolename, adminUsername)
	if err != nil {
		return err
	}

	// External workload user
	externalWorkloadUsername := username("externalworkload")
	log.WithField("etcdUsername", externalWorkloadUsername).
		Info("Configuring external workload user")
	err = ic.addNoPasswordUser(ctx, externalWorkloadUsername)
	if err != nil {
		return err
	}
	externalWorkloadRolename := rolename("externalworkload")
	err = ic.addRole(ctx, externalWorkloadRolename)
	if err != nil {
		return err
	}
	err = ic.grantRoleToUser(ctx, externalWorkloadRolename, externalWorkloadUsername)
	if err != nil {
		return err
	}
	err = ic.grantPermissionToRole(ctx, readOnly, allKeysRange, externalWorkloadRolename)
	if err != nil {
		return err
	}
	err = ic.grantPermissionToRole(ctx, readWrite, rangeForPrefix(store.NodeRegisterStorePrefix), externalWorkloadRolename)
	if err != nil {
		return err
	}
	err = ic.grantPermissionToRole(ctx, readWrite, rangeForPrefix(kvstore.InitLockPath), externalWorkloadRolename)
	if err != nil {
		return err
	}

	// Remote user
	remoteUsername := username("remote")
	log.WithField("etcdUsername", remoteUsername).
		Info("Configuring remote user")
	remoteRolename := rolename("remote")
	err = ic.addNoPasswordUser(ctx, remoteUsername)
	if err != nil {
		return err
	}
	err = ic.addRole(ctx, remoteRolename)
	if err != nil {
		return err
	}
	err = ic.grantRoleToUser(ctx, remoteRolename, remoteUsername)
	if err != nil {
		return err
	}
	err = ic.grantPermissionToRole(ctx, readOnly, allKeysRange, remoteRolename)
	if err != nil {
		return err
	}

	// Post setup
	log.Info("Performing post-init tasks")
	err = ic.enableAuth(ctx)
	if err != nil {
		return err
	}

	return nil
}

// adminUsernameForClusterName generates the admin account username for a given clusterName. This handles the edge case
// where the clusterName is blank, ensuring we don't have a username with a trailing hyphen.
func adminUsernameForClusterName(clusterName string) username {
	if clusterName == "" {
		return "admin"
	}
	return username(fmt.Sprintf("admin-%s", clusterName))
}

// initClient is a thin wrapper around the etcd client library that provides functions with more useful error messages,
// debug logging, and more. It's not intended as an interface for mocking or testing, or to be exposed outside of this
// package. It's entirely an internal implementation detail.
type initClient struct {
	client *clientv3.Client
	log    *logrus.Entry
}

// The username and rolename types exist to make it harder to mix up usernames and rolenames, which are both strings
// and are often the same, in code. Without this there could be subtle bugs where the code still works so long as
// usernames and role names are the same.
type username string
type rolename string

// rootRolename refers to a special "root" role that exists by default in etcd.
const rootRolename = rolename("root")

// put sets a key to a value. It's a wrapper around the etcd client's put method.
func (ic initClient) put(ctx context.Context, key, val string) error {
	ic.log.WithField("etcdKey", key).
		WithField("etcdValue", val).
		Debug("Setting key in etcd")
	_, err := ic.client.Put(ctx, key, val)
	if err != nil {
		return fmt.Errorf("setting path '%s' to '%s': %w", key, val, err)
	}
	return nil
}

// putHasConfigKey sets the specialised etcd "has config" key to be true.
func (ic initClient) putHasConfigKey(ctx context.Context) error {
	ic.log.Debug("Setting the key to indicate that config has already been set")
	err := ic.put(ctx, kvstore.HasClusterConfigPath, "true")
	if err != nil {
		return fmt.Errorf("setting key to indicate config is already set: %w", err)
	}
	return nil
}

// addNoPasswordUser adds a new user to etcd with no password. This is expected as later on we'll enable auth which will
// require other forms of authentication. This is a wrapper around the client's UserAddWithOptions method.
func (ic initClient) addNoPasswordUser(ctx context.Context, username username) error {
	ic.log.WithField("etcdUsername", username).
		Debug("Adding etcd user")
	_, err := ic.client.UserAddWithOptions(ctx, string(username), "", &clientv3.UserAddOptions{NoPassword: true})
	if err != nil {
		return fmt.Errorf("adding user '%s': %w", username, err)
	}
	return nil
}

// addRole adds a new role to etcd. This is a wrapper around the client's RoleAdd method.
func (ic initClient) addRole(ctx context.Context, rolename rolename) error {
	ic.log.WithField("etcdRolename", rolename).
		Debug("Adding etcd role")
	_, err := ic.client.RoleAdd(ctx, string(rolename))
	if err != nil {
		return fmt.Errorf("adding role '%s': %w", rolename, err)
	}
	return nil
}

// grantRoleToUser grants a role to a user, enabling that user access to the permissions of that role. This is a wrapper
// around the client's UserGrantRole method.
func (ic initClient) grantRoleToUser(ctx context.Context, rolename rolename, username username) error {
	ic.log.WithField("etcdUsername", username).
		WithField("etcdRolename", rolename).
		Debug("Granting role to etcd user")
	_, err := ic.client.UserGrantRole(ctx, string(username), string(rolename))
	if err != nil {
		return fmt.Errorf("granting role '%s' to user '%s': %w", rolename, username, err)
	}
	return nil
}

// keyRange describes a range of keys
type keyRange struct {
	start string
	end   string
}

// rangeForPrefix generates a keyRange for a given prefix. This is a wrapper around the client's GetPrefixRangeEnd
// function.
func rangeForPrefix(prefix string) keyRange {
	// For a **prefix** range, we need a trailing slash. Without it, the behaviour of clientv3.GetPrefixRangeEnd is
	// slightly different. For example on `cilium/.initlock` the given range end is `cilium/.initlocl`, while on
	// `cilium/.initlock/` it's `cilium/.initlock0`.
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return keyRange{
		prefix,
		clientv3.GetPrefixRangeEnd(prefix),
	}
}

// allKeysRange is the range over all keys in etcd. Granting permissions on this range is the same as granting global
// permissions in etcd.
var allKeysRange = keyRange{"\x00", "\x00"}

// permission is a thin, internal wrapper around etcd's permission types
type permission clientv3.PermissionType

var readOnly = permission(clientv3.PermRead)
var readWrite = permission(clientv3.PermReadWrite)

func (p permission) string() string {
	return authpb.Permission_Type(p).String()
}

// grantPermissionToRole grants permissions on a range of keys to a role. This is a wrapper around the client's
// RoleGrantPermission method.
func (ic initClient) grantPermissionToRole(ctx context.Context, permission permission, keyRange keyRange, rolename rolename) error {
	ic.log.WithFields(logrus.Fields{
		"etcdRolename":   rolename,
		"etcdPermission": permission.string(),
		"etcdRangeStart": keyRange.start,
		"etcdRangeEnd":   keyRange.end,
	}).
		Debug("Granting permission on a range of keys to an etcd role")
	_, err := ic.client.RoleGrantPermission(ctx, string(rolename), keyRange.start, keyRange.end, clientv3.PermissionType(permission))
	if err != nil {
		return fmt.Errorf("granting role '%s' permission '%s' on range '%s' to '%s': %w", rolename, permission.string(), keyRange.start, keyRange.end, err)
	}
	return nil
}

// enableAuth enables etcd authentication. This is a wrapper around the client's AuthEnable method.
//
// It should be noted that this command should be run **last**, as we usually don't have authentication, so turning
// this on will instantly lock us out.
func (ic initClient) enableAuth(ctx context.Context) error {
	ic.log.Debug("Enabling authentication on etcd cluster")
	_, err := ic.client.AuthEnable(ctx)
	if err != nil {
		return fmt.Errorf("enabling authentication on etcd: %w", err)
	}
	return nil
}
