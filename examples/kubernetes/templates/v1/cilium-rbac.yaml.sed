kind: ClusterRoleBinding
apiVersion: __RBAC_API_VERSION__
metadata:
  name: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium
subjects:
- kind: ServiceAccount
  name: cilium
  namespace: kube-system
- kind: Group
  name: system:nodes
---
kind: ClusterRole
apiVersion: __RBAC_API_VERSION__
metadata:
  name: cilium
rules:
- apiGroups:
  - "networking.k8s.io"
  resources:
  - networkpolicies
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - namespaces
  - services
  - nodes
  - endpoints
  - componentstatuses
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - pods
  - nodes
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - extensions
  resources:
  - networkpolicies #FIXME remove this when we drop support for k8s NP-beta GH-1202
  - thirdpartyresources
  - ingresses
  verbs:
  - create
  - get
  - list
  - watch
- apiGroups:
  - "apiextensions.k8s.io"
  resources:
  - customresourcedefinitions
  verbs:
  - create
  - get
  - list
  - watch
  - update
- apiGroups:
  - cilium.io
  resources:
  - ciliumnetworkpolicies
  - ciliumendpoints
  verbs:
  - "*"
