// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kubernetes_test

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/engine"
	"helm.sh/helm/v4/pkg/strvals"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

const (
	ztunnelSpireValues = "encryption.enabled=true,encryption.type=ztunnel,encryption.ztunnel.ca.type=spire,authentication.mutual.spire.enabled=true,authentication.mutual.spire.install.enabled=true"
	spireCRD           = "encryption.ztunnel.spire.useCRD=true"
	clusterSPIFFEIDAPI = "spire.spiffe.io/v1alpha1/ClusterSPIFFEID"
	// clusterSPIFFEIDCRD is the spire-controller-manager v0.6.2 CRD that users
	// install before enabling useCRD.
	clusterSPIFFEIDCRD = "testdata/spire.spiffe.io_clusterspiffeids.yaml"
	spireServerPath    = "cilium/templates/spire/server/"
	ztunnelCSIDPath    = "cilium/templates/ztunnel/clusterspiffeid.yaml"
	spireIDTemplate    = "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
)

// renderSpireChart renders the cilium chart as helm install does, with the
// given values and overrides, on a cluster that also serves apiVersions.
func renderSpireChart(t *testing.T, values map[string]any, apiVersions []string, overrides ...string) (map[string]string, error) {
	t.Helper()
	chart, err := loader.Load("cilium")
	require.NoError(t, err)
	if values == nil {
		values = map[string]any{}
	}
	for _, override := range overrides {
		require.NoError(t, strvals.ParseInto(override, values))
	}
	caps := common.DefaultCapabilities.Copy()
	caps.APIVersions = append(caps.APIVersions, apiVersions...)
	renderValues, err := chartutil.ToRenderValuesWithSchemaValidation(chart, values,
		common.ReleaseOptions{Name: "cilium", Namespace: "kube-system", IsInstall: true}, caps, false)
	if err != nil {
		return nil, err
	}
	var renderer engine.Engine
	return renderer.RenderWithContext(t.Context(), chart, renderValues)
}

// renderSpire renders the cilium chart on a cluster that serves ClusterSPIFFEIDs.
func renderSpire(t *testing.T, overrides ...string) map[string]string {
	t.Helper()
	rendered, err := renderSpireChart(t, nil, []string{clusterSPIFFEIDAPI}, overrides...)
	require.NoError(t, err)
	return rendered
}

func spireManifest[T any](t *testing.T, rendered map[string]string, path string) T {
	t.Helper()
	require.NotEmpty(t, strings.TrimSpace(rendered[path]), path)
	var resource T
	require.NoError(t, yaml.UnmarshalStrict([]byte(rendered[path]), &resource), path)
	return resource
}

func spireContainer(t *testing.T, pod corev1.PodSpec, name string) corev1.Container {
	t.Helper()
	for _, container := range pod.Containers {
		if container.Name == name {
			return container
		}
	}
	t.Fatalf("container %s not found", name)
	return corev1.Container{}
}

func spireContainerNames(pod corev1.PodSpec) []string {
	names := make([]string, 0, len(pod.Containers))
	for _, container := range pod.Containers {
		names = append(names, container.Name)
	}
	return names
}

func spireVolume(t *testing.T, pod corev1.PodSpec, name string) corev1.Volume {
	t.Helper()
	for _, volume := range pod.Volumes {
		if volume.Name == name {
			return volume
		}
	}
	t.Fatalf("volume %s not found", name)
	return corev1.Volume{}
}

func spireDocuments(t *testing.T, manifest string) []*unstructured.Unstructured {
	t.Helper()
	var documents []*unstructured.Unstructured
	decoder := k8syaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096)
	for {
		document := &unstructured.Unstructured{}
		err := decoder.Decode(&document.Object)
		if errors.Is(err, io.EOF) {
			return documents
		}
		require.NoError(t, err)
		if len(document.Object) > 0 {
			documents = append(documents, document)
		}
	}
}

// spireObjects returns the rendered chart objects of the given kinds, keyed by
// kind, namespace and name.
func spireObjects(t *testing.T, rendered map[string]string, kinds ...string) map[string]*unstructured.Unstructured {
	t.Helper()
	objects := map[string]*unstructured.Unstructured{}
	for path, manifest := range rendered {
		if !strings.HasPrefix(path, "cilium/templates/") || !strings.HasSuffix(path, ".yaml") {
			continue
		}
		for _, object := range spireDocuments(t, manifest) {
			if !slices.Contains(kinds, object.GetKind()) {
				continue
			}
			key := object.GetKind() + "/" + object.GetNamespace() + "/" + object.GetName()
			require.NotContains(t, objects, key, path)
			objects[key] = object
		}
	}
	return objects
}

// spireCRDValidator returns a validator for the ClusterSPIFFEID CRD schema.
func spireCRDValidator(t *testing.T) crdvalidation.SchemaValidator {
	t.Helper()
	data, err := os.ReadFile(clusterSPIFFEIDCRD)
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.UnmarshalStrict(data, &crd))
	require.Equal(t, "clusterspiffeids.spire.spiffe.io", crd.Name)
	require.Equal(t, apiextensionsv1.ClusterScoped, crd.Spec.Scope)
	require.Len(t, crd.Spec.Versions, 1)
	require.Equal(t, "v1alpha1", crd.Spec.Versions[0].Name)
	require.NotNil(t, crd.Spec.Versions[0].Subresources.Status)
	var internal apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &internal, nil))
	validator, _, err := crdvalidation.NewSchemaValidator(&internal)
	require.NoError(t, err)
	return validator
}

// requireUpstreamSpireServerRBAC asserts that the SPIRE server RBAC renders
// exactly as on upstream main, including the fixed spire-server roleRefs and
// the <account>-pod RoleBinding.
func requireUpstreamSpireServerRBAC(t *testing.T, rendered map[string]string, account string, rbac, serviceAccount bool) {
	t.Helper()
	typeMeta := func(kind string) metav1.TypeMeta {
		return metav1.TypeMeta{Kind: kind, APIVersion: "rbac.authorization.k8s.io/v1"}
	}
	subjects := []rbacv1.Subject{{Kind: "ServiceAccount", Name: account, Namespace: "cilium-spire"}}
	if rbac && serviceAccount {
		require.Equal(t, rbacv1.ClusterRole{
			TypeMeta:   typeMeta("ClusterRole"),
			ObjectMeta: metav1.ObjectMeta{Name: account},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"nodes", "nodes/proxy"}, Verbs: []string{"get"}},
			},
		}, spireManifest[rbacv1.ClusterRole](t, rendered, spireServerPath+"clusterrole.yaml"))
		require.Equal(t, rbacv1.ClusterRoleBinding{
			TypeMeta:   typeMeta("ClusterRoleBinding"),
			ObjectMeta: metav1.ObjectMeta{Name: account},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "spire-server"},
			Subjects:   subjects,
		}, spireManifest[rbacv1.ClusterRoleBinding](t, rendered, spireServerPath+"clusterrolebinding.yaml"))
	} else {
		require.Empty(t, strings.TrimSpace(rendered[spireServerPath+"clusterrole.yaml"]))
		require.Empty(t, strings.TrimSpace(rendered[spireServerPath+"clusterrolebinding.yaml"]))
	}
	if serviceAccount {
		require.Equal(t, rbacv1.Role{
			TypeMeta:   typeMeta("Role"),
			ObjectMeta: metav1.ObjectMeta{Name: account, Namespace: "cilium-spire"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"patch", "get", "list"}}},
		}, spireManifest[rbacv1.Role](t, rendered, spireServerPath+"role.yaml"))
	} else {
		require.Empty(t, strings.TrimSpace(rendered[spireServerPath+"role.yaml"]))
	}
	var bindings []rbacv1.RoleBinding
	for _, document := range spireDocuments(t, rendered[spireServerPath+"rolebinding.yaml"]) {
		var binding rbacv1.RoleBinding
		require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(document.Object, &binding))
		bindings = append(bindings, binding)
	}
	require.Equal(t, []rbacv1.RoleBinding{
		{
			TypeMeta:   typeMeta("RoleBinding"),
			ObjectMeta: metav1.ObjectMeta{Name: account, Namespace: "cilium-spire"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "spire-server"},
			Subjects:   subjects,
		},
		{
			TypeMeta:   typeMeta("RoleBinding"),
			ObjectMeta: metav1.ObjectMeta{Name: account + "-pod", Namespace: "cilium-spire"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: account + "-pod"},
			Subjects:   subjects,
		},
	}, bindings)
}

func requireSpireControllerManagerRBAC(t *testing.T, rendered map[string]string, account, namespace string) (rbacv1.ClusterRole, rbacv1.ClusterRoleBinding) {
	t.Helper()
	name := account + "-controller-manager"
	role := spireManifest[rbacv1.ClusterRole](t, rendered, spireServerPath+"controller-manager-clusterrole.yaml")
	require.Equal(t, name, role.Name)
	require.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{"spire.spiffe.io"}, Resources: []string{"clusterspiffeids"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"spire.spiffe.io"}, Resources: []string{"clusterspiffeids/status"}, Verbs: []string{"get", "patch", "update"}},
		{APIGroups: []string{""}, Resources: []string{"pods", "nodes", "namespaces", "endpoints"}, Verbs: []string{"get", "list", "watch"}},
	}, role.Rules)
	binding := spireManifest[rbacv1.ClusterRoleBinding](t, rendered, spireServerPath+"controller-manager-clusterrolebinding.yaml")
	require.Equal(t, name, binding.Name)
	require.Equal(t, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}, binding.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: account, Namespace: namespace}}, binding.Subjects)
	return role, binding
}

// TestSpireUseCRDDisabledKeepsUpstreamRendering checks that without useCRD the
// chart renders the SPIRE server, the SPIRE agent and the operator as on
// upstream main and omits the ztunnel trust domain, so the agent keeps sending
// ztunnel an empty xDS trust domain.
func TestSpireUseCRDDisabledKeepsUpstreamRendering(t *testing.T) {
	for _, tt := range []struct {
		name    string
		values  []string
		managed bool
	}{
		{name: "mutual authentication", values: []string{"authentication.mutual.spire.enabled=true"}, managed: true},
		{name: "ztunnel with chart-managed SPIRE", values: []string{ztunnelSpireValues}, managed: true},
		{name: "ztunnel with external SPIRE", values: []string{ztunnelSpireValues, "authentication.mutual.spire.install.enabled=false"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rendered := renderSpire(t, tt.values...)
			for _, path := range []string{
				ztunnelCSIDPath,
				spireServerPath + "controller-manager-configmap.yaml",
				spireServerPath + "controller-manager-clusterrole.yaml",
				spireServerPath + "controller-manager-clusterrolebinding.yaml",
			} {
				require.Empty(t, strings.TrimSpace(rendered[path]), path)
			}
			ciliumConf := spireManifest[corev1.ConfigMap](t, rendered, "cilium/templates/cilium-configmap.yaml")
			require.NotContains(t, ciliumConf.Data, "ztunnel-spiffe-trust-domain")
			operator := spireManifest[appsv1.Deployment](t, rendered, "cilium/templates/cilium-operator/deployment.yaml")
			require.NotContains(t, spireContainer(t, operator.Spec.Template.Spec, "cilium-operator").Args, "--enable-ztunnel-spiffeid-crd=true")
			if !tt.managed {
				require.Empty(t, strings.TrimSpace(rendered[spireServerPath+"statefulset.yaml"]))
				return
			}
			sts := spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml")
			pod := sts.Spec.Template.Spec
			require.Equal(t, int32(1), *sts.Spec.Replicas)
			require.Equal(t, []string{"cilium-init", "spire-server"}, spireContainerNames(pod))
			require.True(t, *pod.ShareProcessNamespace)
			require.Nil(t, pod.SecurityContext)
			require.Nil(t, pod.Affinity)
			require.Equal(t, &corev1.HostPathVolumeSource{
				Path: "/var/run/spire-server/sockets",
				Type: ptr.To(corev1.HostPathDirectoryOrCreate),
			}, spireVolume(t, pod, "spire-server-socket").HostPath)
			require.NotContains(t, spireContainer(t, pod, "cilium-init").Command[2], "ztunnel")
			serverConf := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"configmap.yaml").Data["server.conf"]
			require.NotContains(t, serverConf, "UpstreamAuthority")
			agentConf := spireManifest[corev1.ConfigMap](t, rendered, "cilium/templates/spire/agent/configmap.yaml").Data["agent.conf"]
			require.NotContains(t, agentConf, "/ztunnel")
			service := spireManifest[corev1.Service](t, rendered, spireServerPath+"service.yaml")
			require.Empty(t, service.Spec.SessionAffinity)
		})
	}
}

// TestSpireClusterSPIFFEID checks the ClusterSPIFFEID that registers enrolled
// workloads, the controller-manager configuration that reconciles it, and the
// ztunnel delegate registration, with custom names everywhere.
func TestSpireClusterSPIFFEID(t *testing.T) {
	rendered := renderSpire(t, ztunnelSpireValues, spireCRD,
		"cluster.name=lab-test,namespaceOverride=network-system,authentication.mutual.spire.trustDomain=workload.test",
		"authentication.mutual.spire.install.namespace=identity-system,authentication.mutual.spire.install.existingNamespace=true",
		"serviceAccounts.ztunnel.name=ztunnel-custom,authentication.mutual.spire.install.server.serviceAccount.name=server-custom",
		"commonLabels.team=networking,authentication.mutual.spire.annotations.owner=platform")

	workloads := spireDocuments(t, rendered[ztunnelCSIDPath])
	require.Len(t, workloads, 1)
	csid := workloads[0]
	require.Equal(t, "spire.spiffe.io/v1alpha1", csid.GetAPIVersion())
	require.Equal(t, "ClusterSPIFFEID", csid.GetKind())
	require.Equal(t, "cilium-spire-network-system-cilium-ztunnel-workloads", csid.GetName())
	require.Empty(t, csid.GetNamespace())
	require.Equal(t, map[string]string{"team": "networking"}, csid.GetLabels())
	require.Equal(t, map[string]string{"owner": "platform"}, csid.GetAnnotations())
	require.Equal(t, map[string]any{
		"className":         "cilium-spire",
		"namespaceSelector": map[string]any{"matchLabels": map[string]any{"io.cilium/mtls-enabled": "true"}},
		"spiffeIDTemplate":  spireIDTemplate,
	}, csid.Object["spec"])
	validator := spireCRDValidator(t)
	require.Empty(t, crdvalidation.ValidateCustomResource(field.NewPath("clusterSPIFFEID"), csid.Object, validator))
	invalid := csid.DeepCopy()
	require.NoError(t, unstructured.SetNestedField(invalid.Object, true, "spec", "spiffeIDTemplate"))
	require.NotEmpty(t, crdvalidation.ValidateCustomResource(field.NewPath("clusterSPIFFEID"), invalid.Object, validator))
	unstructured.RemoveNestedField(invalid.Object, "spec", "spiffeIDTemplate")
	require.NotEmpty(t, crdvalidation.ValidateCustomResource(field.NewPath("clusterSPIFFEID"), invalid.Object, validator))

	// spire-controller-manager renders the template with this data, and ztunnel
	// only accepts the SPIFFE ID of the pod's ServiceAccount.
	parsed, err := template.New("spiffeIDTemplate").Parse(spireIDTemplate)
	require.NoError(t, err)
	var workloadID strings.Builder
	require.NoError(t, parsed.Execute(&workloadID, struct {
		TrustDomain string
		PodMeta     *metav1.ObjectMeta
		PodSpec     *corev1.PodSpec
	}{"workload.test", &metav1.ObjectMeta{Namespace: "shop"}, &corev1.PodSpec{ServiceAccountName: "checkout"}}))
	require.Equal(t, "spiffe://workload.test/ns/shop/sa/checkout", workloadID.String())

	cm := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"controller-manager-configmap.yaml")
	require.Equal(t, "identity-system", cm.Namespace)
	var cfg map[string]any
	require.NoError(t, yaml.UnmarshalStrict([]byte(cm.Data["controller-manager.yaml"]), &cfg))
	require.Equal(t, map[string]any{
		"apiVersion":            "spire.spiffe.io/v1alpha1",
		"kind":                  "ControllerManagerConfig",
		"metrics":               map[string]any{"bindAddress": "0"},
		"health":                map[string]any{"healthProbeBindAddress": "0.0.0.0:8082"},
		"leaderElection":        map[string]any{"leaderElect": false},
		"clusterName":           "lab-test",
		"trustDomain":           "workload.test",
		"spireServerSocketPath": "/tmp/spire-server/private/api.sock",
		"className":             "cilium-spire",
		"watchClassless":        false,
		"entryIDPrefix":         "cilium",
		"reconcile":             map[string]any{"clusterSPIFFEIDs": true, "clusterStaticEntries": false, "clusterFederatedTrustDomains": false},
		"logLevel":              "info",
	}, cfg)
	// The controller-manager derives each entry's parent ID from the cluster
	// name, so it must match the cluster of the k8s_psat node attestor.
	serverConf := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"configmap.yaml").Data["server.conf"]
	require.Contains(t, serverConf, `"lab-test" = {`)
	require.Contains(t, serverConf, `trust_domain = "workload.test"`)

	sts := spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml")
	require.Equal(t, "identity-system", sts.Namespace)
	require.Equal(t, "server-custom", sts.Spec.Template.Spec.ServiceAccountName)
	script := spireContainer(t, sts.Spec.Template.Spec, "cilium-init").Command[2]
	require.Contains(t, script, `ZTUNNEL_SPIFFE_ID="spiffe://workload.test/ztunnel"`)
	require.Contains(t, script, `ZTUNNEL_SELECTORS="-selector k8s:ns:network-system -selector k8s:sa:ztunnel-custom"`)
	require.Contains(t, script, "entry create ${SOCKET_FLAG} -spiffeID $ZTUNNEL_SPIFFE_ID -parentID $AGENT_SPIFFE_ID $ZTUNNEL_SELECTORS")
	ztunnel := spireManifest[appsv1.DaemonSet](t, rendered, "cilium/templates/ztunnel/daemonset.yaml")
	require.Equal(t, "network-system", ztunnel.Namespace)
	require.Equal(t, "ztunnel-custom", ztunnel.Spec.Template.Spec.ServiceAccountName)
	agentConf := spireManifest[corev1.ConfigMap](t, rendered, "cilium/templates/spire/agent/configmap.yaml").Data["agent.conf"]
	require.Contains(t, agentConf, `"spiffe://workload.test/cilium-agent",`)
	require.Contains(t, agentConf, `"spiffe://workload.test/ztunnel",`)

	ciliumConf := spireManifest[corev1.ConfigMap](t, rendered, "cilium/templates/cilium-configmap.yaml")
	require.Equal(t, "workload.test", ciliumConf.Data["mesh-auth-spiffe-trust-domain"])
	require.Equal(t, "workload.test", ciliumConf.Data["ztunnel-spiffe-trust-domain"])
	operator := spireManifest[appsv1.Deployment](t, rendered, "cilium/templates/cilium-operator/deployment.yaml")
	require.Contains(t, spireContainer(t, operator.Spec.Template.Spec, "cilium-operator").Args, "--enable-ztunnel-spiffeid-crd=true")

	controllerRole, controllerBinding := requireSpireControllerManagerRBAC(t, rendered, "server-custom", "identity-system")
	for _, meta := range []metav1.ObjectMeta{controllerRole.ObjectMeta, controllerBinding.ObjectMeta} {
		require.Equal(t, map[string]string{"team": "networking"}, meta.Labels)
		require.Equal(t, map[string]string{"owner": "platform"}, meta.Annotations)
	}
}

// TestSpireClassName checks that the controller-manager reconciles only the
// ClusterSPIFFEIDs of its class, or only classless ones without a class.
func TestSpireClassName(t *testing.T) {
	for _, className := range []string{"", "custom-class"} {
		t.Run("className="+className, func(t *testing.T) {
			rendered := renderSpire(t, ztunnelSpireValues, spireCRD, "encryption.ztunnel.spire.className="+className)
			cm := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"controller-manager-configmap.yaml")
			var cfg map[string]any
			require.NoError(t, yaml.UnmarshalStrict([]byte(cm.Data["controller-manager.yaml"]), &cfg))
			want := map[string]any{"watchClassless": className == ""}
			if className != "" {
				want["className"] = className
			}
			got := map[string]any{}
			for _, key := range []string{"className", "watchClassless"} {
				if value, found := cfg[key]; found {
					got[key] = value
				}
			}
			require.Equal(t, want, got)

			workloads := spireDocuments(t, rendered[ztunnelCSIDPath])
			require.Len(t, workloads, 1)
			value, found, err := unstructured.NestedString(workloads[0].Object, "spec", "className")
			require.NoError(t, err)
			require.Equal(t, className != "", found)
			require.Equal(t, className, value)
		})
	}
}

// TestSpireControllerManagerSidecar checks the controller-manager sidecar and
// that cilium-init, which reaches the SPIRE server API socket through
// /proc/<pid>/root, runs as the SPIRE server image's user by default.
func TestSpireControllerManagerSidecar(t *testing.T) {
	serverUser := &corev1.PodSecurityContext{RunAsUser: ptr.To[int64](1000), RunAsGroup: ptr.To[int64](1000), FSGroup: ptr.To[int64](1000)}
	rendered := renderSpire(t, ztunnelSpireValues, spireCRD)
	sts := spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml")
	pod := sts.Spec.Template.Spec
	require.Equal(t, int32(1), *sts.Spec.Replicas)
	require.Equal(t, []string{"cilium-init", "spire-server", "spire-controller-manager"}, spireContainerNames(pod))
	require.True(t, *pod.ShareProcessNamespace)
	require.Equal(t, serverUser, pod.SecurityContext)
	command := spireContainer(t, pod, "cilium-init").Command
	require.Equal(t, []string{"/bin/sh", "-c"}, command[:2])
	for _, entry := range []string{"agent", "cilium-agent", "cilium-operator", "ztunnel"} {
		require.Contains(t, command[2], `echo "Ensuring `+entry+` entry`)
	}

	server := spireContainer(t, pod, "spire-server")
	require.Contains(t, server.VolumeMounts, corev1.VolumeMount{Name: "spire-server-socket", MountPath: "/tmp/spire-server/private"})
	require.Equal(t, corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, spireVolume(t, pod, "spire-server-socket").VolumeSource)
	require.Equal(t, "spire-controller-manager", spireVolume(t, pod, "spire-controller-config").ConfigMap.Name)
	controller := spireContainer(t, pod, "spire-controller-manager")
	require.Contains(t, controller.Image, "ghcr.io/spiffe/spire-controller-manager:0.6.2@sha256:")
	require.Equal(t, []string{"-config", "/run/spire/controller-manager/controller-manager.yaml"}, controller.Args)
	require.Equal(t, []corev1.EnvVar{{Name: "ENABLE_WEBHOOKS", Value: "false"}}, controller.Env)
	require.Equal(t, []corev1.ContainerPort{{Name: "controller-http", ContainerPort: 8082}}, controller.Ports)
	require.Equal(t, []corev1.VolumeMount{
		{Name: "spire-controller-config", MountPath: "/run/spire/controller-manager", ReadOnly: true},
		{Name: "spire-server-socket", MountPath: "/tmp/spire-server/private", ReadOnly: true},
	}, controller.VolumeMounts)
	port := intstr.FromString("controller-http")
	require.Equal(t, &corev1.Probe{
		ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: port}},
		InitialDelaySeconds: 15,
		PeriodSeconds:       10,
	}, controller.LivenessProbe)
	require.Equal(t, &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: port}},
		PeriodSeconds: 5,
	}, controller.ReadinessProbe)
	require.Nil(t, controller.SecurityContext)
	require.Empty(t, controller.Resources)

	rendered = renderSpire(t, ztunnelSpireValues, spireCRD,
		"authentication.mutual.spire.install.server.podSecurityContext.fsGroup=2000,authentication.mutual.spire.install.server.podSecurityContext.runAsNonRoot=true",
		"authentication.mutual.spire.install.server.securityContext.runAsUser=3000",
		"authentication.mutual.spire.install.server.controllerManager.image.override=registry.example/controller:custom",
		"authentication.mutual.spire.install.server.controllerManager.resources.requests.cpu=150m")
	pod = spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml").Spec.Template.Spec
	require.Equal(t, &corev1.PodSecurityContext{
		RunAsUser:    ptr.To[int64](1000),
		RunAsGroup:   ptr.To[int64](1000),
		FSGroup:      ptr.To[int64](2000),
		RunAsNonRoot: ptr.To(true),
	}, pod.SecurityContext)
	for _, name := range []string{"spire-server", "spire-controller-manager"} {
		require.Equal(t, &corev1.SecurityContext{RunAsUser: ptr.To[int64](3000)}, spireContainer(t, pod, name).SecurityContext, name)
	}
	controller = spireContainer(t, pod, "spire-controller-manager")
	require.Equal(t, "registry.example/controller:custom", controller.Image)
	require.Equal(t, "150m", controller.Resources.Requests.Cpu().String())

	for _, useCRD := range []bool{false, true} {
		rendered := renderSpire(t, ztunnelSpireValues, fmt.Sprintf("encryption.ztunnel.spire.useCRD=%t", useCRD),
			"authentication.mutual.spire.install.server.podSecurityContext=null")
		securityContext := spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml").Spec.Template.Spec.SecurityContext
		if useCRD {
			require.Equal(t, serverUser, securityContext)
		} else {
			require.Nil(t, securityContext)
		}
	}
}

// TestSpireUseCRDOnlyAddsControllerManagerRBAC checks that toggling useCRD only
// adds or removes the controller-manager ClusterRole and ClusterRoleBinding and
// never changes another RBAC object, such as an immutable roleRef.
func TestSpireUseCRDOnlyAddsControllerManagerRBAC(t *testing.T) {
	kinds := []string{"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}
	for _, account := range []string{"spire-server", "server-custom"} {
		for _, rbac := range []bool{false, true} {
			for _, serviceAccount := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/rbac=%t/serviceAccount=%t", account, rbac, serviceAccount), func(t *testing.T) {
					values := []string{
						ztunnelSpireValues,
						"authentication.mutual.spire.install.server.serviceAccount.name=" + account,
						fmt.Sprintf("rbac.create=%t", rbac),
						fmt.Sprintf("authentication.mutual.spire.install.server.serviceAccount.create=%t", serviceAccount),
					}
					off := renderSpire(t, values...)
					requireUpstreamSpireServerRBAC(t, off, account, rbac, serviceAccount)
					on := renderSpire(t, append(slices.Clone(values), spireCRD)...)
					for _, name := range []string{"clusterrole.yaml", "clusterrolebinding.yaml", "role.yaml", "rolebinding.yaml"} {
						require.Equal(t, off[spireServerPath+name], on[spireServerPath+name], name)
					}
					before, after := spireObjects(t, off, kinds...), spireObjects(t, on, kinds...)
					for key, object := range before {
						require.Contains(t, after, key)
						require.Equal(t, object.Object, after[key].Object, key)
					}
					var added []string
					for key := range after {
						if _, found := before[key]; !found {
							added = append(added, key)
						}
					}
					if rbac && serviceAccount {
						name := account + "-controller-manager"
						require.ElementsMatch(t, []string{"ClusterRole//" + name, "ClusterRoleBinding//" + name}, added)
						requireSpireControllerManagerRBAC(t, on, account, "cilium-spire")
					} else {
						require.Empty(t, added)
					}
				})
			}
		}
	}
}

// TestSpireCRDPrerequisites checks that useCRD requires the chart-managed SPIRE
// CA for ztunnel and the ClusterSPIFFEID CRD of the bundled controller-manager.
func TestSpireCRDPrerequisites(t *testing.T) {
	_, err := renderSpireChart(t, nil, nil, ztunnelSpireValues, spireCRD)
	require.ErrorContains(t, err, "requires the spire.spiffe.io/v1alpha1 ClusterSPIFFEID CRD. Please install it with kubectl apply --server-side -f https://raw.githubusercontent.com/spiffe/spire-controller-manager/v0.6.2/config/crd/bases/spire.spiffe.io_clusterspiffeids.yaml")
	for _, tag := range []string{"v0.7.1", "0.7.1@sha256:" + strings.Repeat("0", 64)} {
		_, err := renderSpireChart(t, nil, nil, ztunnelSpireValues, spireCRD, "authentication.mutual.spire.install.server.controllerManager.image.tag="+tag)
		require.ErrorContains(t, err, "https://raw.githubusercontent.com/spiffe/spire-controller-manager/v0.7.1/config/crd/bases/spire.spiffe.io_clusterspiffeids.yaml")
	}
	_, err = renderSpireChart(t, nil, nil, ztunnelSpireValues, spireCRD, "encryption.ztunnel.spire.trustCRDsExist=true")
	require.NoError(t, err)
	_, err = renderSpireChart(t, nil, []string{clusterSPIFFEIDAPI}, ztunnelSpireValues, spireCRD)
	require.NoError(t, err)

	for _, override := range []string{
		"encryption.enabled=false",
		"encryption.type=wireguard",
		"encryption.ztunnel.ca.type=internal",
		"authentication.mutual.spire.enabled=false",
		"authentication.mutual.spire.install.enabled=false",
	} {
		t.Run(override, func(t *testing.T) {
			_, err := renderSpireChart(t, nil, []string{clusterSPIFFEIDAPI}, ztunnelSpireValues, spireCRD, override)
			require.ErrorContains(t, err, "encryption.ztunnel.spire.useCRD=true requires encryption.enabled=true, encryption.type=ztunnel, encryption.ztunnel.ca.type=spire, authentication.mutual.spire.enabled=true and authentication.mutual.spire.install.enabled=true")
		})
	}
}

func TestSpirePreservesInternalCATrustDomain(t *testing.T) {
	rendered := renderSpire(t, ztunnelSpireValues, "encryption.ztunnel.ca.type=internal")
	ciliumConf := spireManifest[corev1.ConfigMap](t, rendered, "cilium/templates/cilium-configmap.yaml")
	require.Equal(t, "spiffe.cilium", ciliumConf.Data["mesh-auth-spiffe-trust-domain"])
	require.NotContains(t, ciliumConf.Data, "ztunnel-spiffe-trust-domain")
}

// TestSpireServerReplicas checks that multiple SPIRE servers each keep their
// own datastore, sign with one shared upstream root and run on separate nodes.
func TestSpireServerReplicas(t *testing.T) {
	for _, tt := range []struct {
		name           string
		values         []string
		replicas       int32
		upstreamSecret string
	}{
		{name: "one server", replicas: 1},
		{name: "two servers", values: []string{"authentication.mutual.spire.install.server.replicas=2"}, replicas: 2, upstreamSecret: "spire-upstream-ca"},
		{name: "three servers", values: []string{"authentication.mutual.spire.install.server.replicas=3"}, replicas: 3, upstreamSecret: "spire-upstream-ca"},
		{name: "one server with a custom root", values: []string{"authentication.mutual.spire.install.server.ca.upstreamSecret=custom-root"}, replicas: 1, upstreamSecret: "custom-root"},
		{name: "two servers with a custom root", values: []string{"authentication.mutual.spire.install.server.replicas=2,authentication.mutual.spire.install.server.ca.upstreamSecret=custom-root"}, replicas: 2, upstreamSecret: "custom-root"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rendered := renderSpire(t, append([]string{ztunnelSpireValues, spireCRD}, tt.values...)...)
			sts := spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml")
			pod := sts.Spec.Template.Spec
			require.Equal(t, tt.replicas, *sts.Spec.Replicas)
			server := spireContainer(t, pod, "spire-server")
			serverConf := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"configmap.yaml").Data["server.conf"]
			require.Contains(t, serverConf, `KeyManager "disk"`)
			require.Len(t, sts.Spec.VolumeClaimTemplates, 1)
			require.Equal(t, "spire-data", sts.Spec.VolumeClaimTemplates[0].Name)
			require.Contains(t, server.VolumeMounts, corev1.VolumeMount{Name: "spire-data", MountPath: "/run/spire/data"})
			for _, volume := range pod.Volumes {
				require.NotEqual(t, "spire-data", volume.Name, "every server needs its own claim")
			}

			if tt.upstreamSecret == "" {
				require.NotContains(t, serverConf, "UpstreamAuthority")
				for _, volume := range pod.Volumes {
					require.NotEqual(t, "spire-upstream-ca", volume.Name)
				}
			} else {
				require.Contains(t, serverConf, `UpstreamAuthority "disk"`)
				require.Contains(t, serverConf, `cert_file_path = "/run/spire/upstream/tls.crt"`)
				require.Contains(t, serverConf, `key_file_path = "/run/spire/upstream/tls.key"`)
				require.Equal(t, &corev1.SecretVolumeSource{
					SecretName:  tt.upstreamSecret,
					DefaultMode: ptr.To[int32](0o440),
					Items:       []corev1.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}},
				}, spireVolume(t, pod, "spire-upstream-ca").Secret)
				require.Contains(t, server.VolumeMounts, corev1.VolumeMount{Name: "spire-upstream-ca", MountPath: "/run/spire/upstream", ReadOnly: true})
			}

			service := spireManifest[corev1.Service](t, rendered, spireServerPath+"service.yaml")
			if tt.replicas == 1 {
				require.Empty(t, service.Spec.SessionAffinity)
				require.Nil(t, pod.Affinity)
				return
			}
			require.Equal(t, corev1.ServiceAffinityClientIP, service.Spec.SessionAffinity)
			require.Equal(t, &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
					LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "spire-server"}},
					TopologyKey:   "kubernetes.io/hostname",
				}},
			}}, pod.Affinity)
		})
	}

	t.Run("custom affinity", func(t *testing.T) {
		rendered := renderSpire(t, ztunnelSpireValues, spireCRD, "authentication.mutual.spire.install.server.replicas=2",
			"authentication.mutual.spire.install.server.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight=100,authentication.mutual.spire.install.server.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.topologyKey=kubernetes.io/hostname")
		require.Equal(t, &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
				Weight:          100,
				PodAffinityTerm: corev1.PodAffinityTerm{TopologyKey: "kubernetes.io/hostname"},
			}},
		}}, spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml").Spec.Template.Spec.Affinity)
	})

	t.Run("scale up keeps the pod template", func(t *testing.T) {
		const storage = "authentication.mutual.spire.install.server.dataStorage.storageClass=managed-csi,authentication.mutual.spire.install.server.dataStorage.size=2Gi"
		before := spireManifest[appsv1.StatefulSet](t, renderSpire(t, ztunnelSpireValues, spireCRD, storage, "authentication.mutual.spire.install.server.replicas=2"), spireServerPath+"statefulset.yaml")
		after := spireManifest[appsv1.StatefulSet](t, renderSpire(t, ztunnelSpireValues, spireCRD, storage, "authentication.mutual.spire.install.server.replicas=3"), spireServerPath+"statefulset.yaml")
		require.Equal(t, int32(3), *after.Spec.Replicas)
		require.Equal(t, before.Spec.Template, after.Spec.Template)
		require.Equal(t, before.Spec.VolumeClaimTemplates, after.Spec.VolumeClaimTemplates)
		require.Equal(t, "managed-csi", *before.Spec.VolumeClaimTemplates[0].Spec.StorageClassName)
		require.Equal(t, "2Gi", before.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests.Storage().String())
	})

	t.Run("upstream root needs useCRD", func(t *testing.T) {
		rendered := renderSpire(t, ztunnelSpireValues, "authentication.mutual.spire.install.server.ca.upstreamSecret=custom-root")
		serverConf := spireManifest[corev1.ConfigMap](t, rendered, spireServerPath+"configmap.yaml").Data["server.conf"]
		require.NotContains(t, serverConf, "UpstreamAuthority")
		for _, volume := range spireManifest[appsv1.StatefulSet](t, rendered, spireServerPath+"statefulset.yaml").Spec.Template.Spec.Volumes {
			require.NotEqual(t, "spire-upstream-ca", volume.Name)
		}
	})
}

// TestSpireInvalidServerConfigurations checks that multiple SPIRE servers
// require useCRD and that the schema rejects invalid replicas and root names.
func TestSpireInvalidServerConfigurations(t *testing.T) {
	for _, values := range []string{"authentication.mutual.spire.enabled=true", ztunnelSpireValues} {
		_, err := renderSpireChart(t, nil, nil, values, "authentication.mutual.spire.install.server.replicas=2")
		require.ErrorContains(t, err, "Multiple SPIRE servers require encryption.ztunnel.spire.useCRD=true")
	}

	server := func(values map[string]any) map[string]any {
		return map[string]any{"authentication": map[string]any{"mutual": map[string]any{"spire": map[string]any{
			"install": map[string]any{"server": values},
		}}}}
	}
	for _, value := range []any{0, -1, 2147483648, 1.5, "2", "many", true} {
		t.Run(fmt.Sprintf("replicas=%#v", value), func(t *testing.T) {
			_, err := renderSpireChart(t, server(map[string]any{"replicas": value}), []string{clusterSPIFFEIDAPI}, ztunnelSpireValues, spireCRD)
			require.ErrorContains(t, err, "/replicas")
		})
	}
	for _, value := range []any{"bad_name", true} {
		t.Run(fmt.Sprintf("upstreamSecret=%#v", value), func(t *testing.T) {
			_, err := renderSpireChart(t, server(map[string]any{"ca": map[string]any{"upstreamSecret": value}}), []string{clusterSPIFFEIDAPI}, ztunnelSpireValues, spireCRD)
			require.ErrorContains(t, err, "/upstreamSecret")
		})
	}
}
