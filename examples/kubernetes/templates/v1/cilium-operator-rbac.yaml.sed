---
kind: ServiceAccount
apiVersion: v1
metadata:
  name: cilium-operator
  namespace: kube-system
---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRole
metadata:
  name: cilium-operator
  namespace: kube-system
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - deployments
  - componentstatuses
  verbs:
  - '*'
- apiGroups:
  - ""
  resources:
  - services
  - endpoints
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - cilium.io
  resources:
  - ciliumnetworkpolicies
  - ciliumnetworkpolicies/status
  - ciliumendpoints
  - ciliumendpoints/status
  verbs:
  - '*'
---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRoleBinding
metadata:
  name: cilium-operator
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium-operator
subjects:
- kind: ServiceAccount
  name: cilium-operator
  namespace: kube-system
