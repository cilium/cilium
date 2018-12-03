apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: cilium-lb
  namespace: kube-system
spec:
  template:
    metadata:
      labels:
        k8s-app: cilium
        kubernetes.io/cluster-service: "true"
      annotations:
       # This annotation plus the CriticalAddonsOnly toleration makes
       # cilium to be a critical pod in the cluster, which ensures cilium
       # gets priority scheduling.
       # https://kubernetes.io/docs/tasks/administer-cluster/guaranteed-scheduling-critical-addon-pods/
        scheduler.alpha.kubernetes.io/critical-pod: ''

    spec:
      serviceAccountName: cilium
      containers:
      - image: cilium/cilium:local_build
        imagePullPolicy: Never
        name: cilium-agent
        command: [ "cilium-agent" ]
        args:
          - "--debug"
          - "--lb"
          - "$(IFACE)"
          - "-d"
          - "$(IFACE)"
          - "--kvstore"
          - "etcd"
          - "--kvstore-opt"
          - "etcd.config=/var/lib/cilium/etcd-config.yml"
          - "--k8s-kubeconfig-path"
          - "/var/lib/cilium/kubeconfig"
        lifecycle:
          postStart:
            exec:
              command:
                - "/cni-install.sh"
          preStop:
            exec:
              command:
                - "/cni-uninstall.sh"
        env:
          - name: "K8S_NODE_NAME"
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: "IFACE"
            value: "$iface"
          - name: "DISABLE_IPV4"
            value: "$disable_ipv4"
        volumeMounts:
          - name: bpf-maps
            mountPath: /sys/fs/bpf
          - name: cilium-run
            mountPath: /var/run/cilium
          - name: cilium-lib
            mountPath: /var/lib/cilium
          - name: cni-path
            mountPath: /host/opt/cni/bin
          - name: etc-cni-netd
            mountPath: /host/etc/cni/net.d
          - name: docker-socket
            mountPath: /var/run/docker.sock
            readOnly: true
        securityContext:
          capabilities:
            add:
              - "NET_ADMIN"
          privileged: true
      hostNetwork: true
      volumes:
        - name: cilium-run
          hostPath:
            path: /var/run/cilium
        - name: cilium-lib
          hostPath:
            path: /var/lib/cilium
        - name: cni-path
          hostPath:
            path: /opt/cni/bin
        - name: bpf-maps
          hostPath:
            path: /sys/fs/bpf
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock
        - name: etc-cni-netd
          hostPath:
              path: /etc/cni/net.d
      tolerations:
      # Mark cilium's pod as critical for rescheduling
      - key: CriticalAddonsOnly
        operator: "Exists"
