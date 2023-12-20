// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
	yamlUtils "github.com/cilium/cilium-cli/utils/yaml"
)

func (k *K8sInstaller) NewServiceAccount(name string) *corev1.ServiceAccount {
	var (
		saFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		switch name {
		case defaults.AgentServiceAccountName:
			saFileName = "templates/cilium-agent/serviceaccount.yaml"
		case defaults.OperatorServiceAccountName:
			saFileName = "templates/cilium-operator/serviceaccount.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		switch name {
		case defaults.AgentServiceAccountName:
			saFileName = "templates/cilium-agent-serviceaccount.yaml"
		case defaults.OperatorServiceAccountName:
			saFileName = "templates/cilium-operator-serviceaccount.yaml"
		}
	}

	saFile := k.manifests[saFileName]

	var sa corev1.ServiceAccount
	yamlUtils.MustUnmarshal([]byte(saFile), &sa)
	return &sa
}

func (k *K8sInstaller) NewClusterRole(name string) *rbacv1.ClusterRole {
	var (
		crFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		switch name {
		case defaults.AgentServiceAccountName:
			crFileName = "templates/cilium-agent/clusterrole.yaml"
		case defaults.OperatorServiceAccountName:
			crFileName = "templates/cilium-operator/clusterrole.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		switch name {
		case defaults.AgentServiceAccountName:
			crFileName = "templates/cilium-agent-clusterrole.yaml"
		case defaults.OperatorServiceAccountName:
			crFileName = "templates/cilium-operator-clusterrole.yaml"
		}
	}

	crFile := k.manifests[crFileName]

	var cr rbacv1.ClusterRole
	yamlUtils.MustUnmarshal([]byte(crFile), &cr)
	return &cr
}

func (k *K8sInstaller) NewClusterRoleBinding(crbName string) *rbacv1.ClusterRoleBinding {
	var (
		crbFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		switch crbName {
		case defaults.AgentClusterRoleName:
			crbFileName = "templates/cilium-agent/clusterrolebinding.yaml"
		case defaults.OperatorClusterRoleName:
			crbFileName = "templates/cilium-operator/clusterrolebinding.yaml"
		}
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		switch crbName {
		case defaults.AgentClusterRoleName:
			crbFileName = "templates/cilium-agent-clusterrolebinding.yaml"
		case defaults.OperatorClusterRoleName:
			crbFileName = "templates/cilium-operator-clusterrolebinding.yaml"
		}
	}

	crbFile := k.manifests[crbFileName]

	var crb rbacv1.ClusterRoleBinding
	yamlUtils.MustUnmarshal([]byte(crbFile), &crb)
	return &crb
}

func (k *K8sInstaller) NewRole(name string) []*rbacv1.Role {
	var (
		roleFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.11.99")(k.chartVersion):
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

	roles := yamlUtils.MustUnmarshalMulti[*rbacv1.Role]([]byte(rFile))
	out := []*rbacv1.Role{}
	for _, role := range roles {
		if role != nil {
			out = append(out, role)
		}
	}
	return out
}

func (k *K8sInstaller) NewRoleBinding(crbName string) []*rbacv1.RoleBinding {
	var (
		rbFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.11.99")(k.chartVersion):
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

	rbs := yamlUtils.MustUnmarshalMulti[*rbacv1.RoleBinding]([]byte(rbFile))
	out := []*rbacv1.RoleBinding{}
	for _, rb := range rbs {
		if rb != nil {
			out = append(out, rb)
		}
	}
	return out
}
