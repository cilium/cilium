---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRole
metadata:
  name: cilium-etcd-operator
rules:
- apiGroups:
  - etcd.database.coreos.com
  resources:
  - etcdclusters
  verbs:
  - get
  - delete
  - create
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - delete
  - get
  - create
- apiGroups:
  - ""
  resources:
  - deployments
  verbs:
  - delete
  - create
  - get
  - update
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - list
  - delete
  - get
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - delete
  - create
  - get
  - update
- apiGroups:
  - ""
  resources:
  - componentstatuses
  verbs:
  - get
- apiGroups:
  - extensions
  resources:
  - deployments
  verbs:
  - delete
  - create
  - get
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - create
  - delete
---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRoleBinding
metadata:
  name: cilium-etcd-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium-etcd-operator
subjects:
- kind: ServiceAccount
  name: cilium-etcd-operator
  namespace: kube-system
---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRole
metadata:
  name: etcd-operator
rules:
- apiGroups:
  - etcd.database.coreos.com
  resources:
  - etcdclusters
  - etcdbackups
  - etcdrestores
  verbs:
  - '*'
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - '*'
- apiGroups:
  - ""
  resources:
  - pods
  - services
  - endpoints
  - persistentvolumeclaims
  - events
  - deployments
  verbs:
  - '*'
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - '*'
- apiGroups:
  - extensions
  resources:
  - deployments
  verbs:
  - create
  - get
  - list
  - patch
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
---
apiVersion: __RBAC_API_VERSION__
kind: ClusterRoleBinding
metadata:
  name: etcd-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: etcd-operator
subjects:
- kind: ServiceAccount
  name: cilium-etcd-sa
  namespace: kube-system
