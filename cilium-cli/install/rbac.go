// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
)

func (k *K8sInstaller) NewServiceAccount(name string) *corev1.ServiceAccount {
	var (
		saFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch name {
		case defaults.AgentServiceAccountName:
			saFileName = "templates/cilium-agent/serviceaccount.yaml"
		case defaults.OperatorServiceAccountName:
			saFileName = "templates/cilium-operator/serviceaccount.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch name {
		case defaults.AgentServiceAccountName:
			saFileName = "templates/cilium-agent-serviceaccount.yaml"
		case defaults.OperatorServiceAccountName:
			saFileName = "templates/cilium-operator-serviceaccount.yaml"
		}
	}

	saFile := k.manifests[saFileName]

	var sa corev1.ServiceAccount
	utils.MustUnmarshalYAML([]byte(saFile), &sa)
	return &sa
}

func (k *K8sInstaller) NewClusterRole(name string) *rbacv1.ClusterRole {
	var (
		crFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch name {
		case defaults.AgentServiceAccountName:
			crFileName = "templates/cilium-agent/clusterrole.yaml"
		case defaults.OperatorServiceAccountName:
			crFileName = "templates/cilium-operator/clusterrole.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch name {
		case defaults.AgentServiceAccountName:
			crFileName = "templates/cilium-agent-clusterrole.yaml"
		case defaults.OperatorServiceAccountName:
			crFileName = "templates/cilium-operator-clusterrole.yaml"
		}
	}

	crFile := k.manifests[crFileName]

	var cr rbacv1.ClusterRole
	utils.MustUnmarshalYAML([]byte(crFile), &cr)
	return &cr
}

func (k *K8sInstaller) NewClusterRoleBinding(crbName string) *rbacv1.ClusterRoleBinding {
	var (
		crbFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		switch crbName {
		case defaults.AgentClusterRoleName:
			crbFileName = "templates/cilium-agent/clusterrolebinding.yaml"
		case defaults.OperatorClusterRoleName:
			crbFileName = "templates/cilium-operator/clusterrolebinding.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		switch crbName {
		case defaults.AgentClusterRoleName:
			crbFileName = "templates/cilium-agent-clusterrolebinding.yaml"
		case defaults.OperatorClusterRoleName:
			crbFileName = "templates/cilium-operator-clusterrolebinding.yaml"
		}
	}

	crbFile := k.manifests[crbFileName]

	var crb rbacv1.ClusterRoleBinding
	utils.MustUnmarshalYAML([]byte(crbFile), &crb)
	return &crb
}

func (k *K8sInstaller) NewRole(name string) *rbacv1.Role {
	var (
		roleFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.11.99")(ciliumVer):
		switch name {
		case defaults.AgentSecretsRoleName:
			roleFileName = "templates/cilium-agent/role.yaml"
		case defaults.OperatorSecretsRoleName:
			roleFileName = "templates/cilium-operator/role.yaml"
		}
	}

	rFile, exists := k.manifests[roleFileName]
	if !exists {
		return nil
	}

	var cr rbacv1.Role
	utils.MustUnmarshalYAML([]byte(rFile), &cr)
	return &cr
}

func (k *K8sInstaller) NewRoleBinding(crbName string) *rbacv1.RoleBinding {
	var (
		rbFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.11.99")(ciliumVer):
		switch crbName {
		case defaults.AgentSecretsRoleName:
			rbFileName = "templates/cilium-agent/rolebinding.yaml"
		case defaults.OperatorSecretsRoleName:
			rbFileName = "templates/cilium-operator/rolebinding.yaml"
		}
	}

	rbFile, exists := k.manifests[rbFileName]
	if !exists {
		return nil
	}
	var crb rbacv1.RoleBinding
	utils.MustUnmarshalYAML([]byte(rbFile), &crb)
	return &crb
}
