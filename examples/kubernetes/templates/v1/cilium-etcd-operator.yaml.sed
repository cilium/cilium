---
apiVersion: __DEPLOYMENT_API_VERSION__
kind: Deployment
metadata:
  labels:
    io.cilium/app: etcd-operator
    name: cilium-etcd-operator
  name: cilium-etcd-operator
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      io.cilium/app: etcd-operator
      name: cilium-etcd-operator
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
    type: RollingUpdate
  template:
    metadata:
      labels:
        io.cilium/app: etcd-operator
        name: cilium-etcd-operator
    spec:
      containers:
      - command:
        - /usr/bin/cilium-etcd-operator
        env:
        - name: CILIUM_ETCD_OPERATOR_CLUSTER_DOMAIN
          value: cluster.local
        - name: CILIUM_ETCD_OPERATOR_ETCD_CLUSTER_SIZE
          value: "3"
        - name: CILIUM_ETCD_OPERATOR_NAMESPACE
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
        - name: CILIUM_ETCD_OPERATOR_POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: CILIUM_ETCD_OPERATOR_POD_UID
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.uid
        image: docker.io/cilium/cilium-etcd-operator:__CILIUM_ETCD_OPERATOR_VERSION__
        imagePullPolicy: IfNotPresent
        name: cilium-etcd-operator
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      serviceAccount: cilium-etcd-operator
      serviceAccountName: cilium-etcd-operator
      tolerations:
      - operator: Exists
