kind: DaemonSet
apiVersion: __DS_API_VERSION__
metadata:
  name: cilium
  namespace: kube-system
spec:
  updateStrategy:
    type: "RollingUpdate"
    rollingUpdate:
      # Specifies the maximum number of Pods that can be unavailable during the update process.
      # The current default value is 1 or 100% for daemonsets; Adding an explicit value here
      # to avoid confusion, as the default value is specific to the type (daemonset/deployment).
      maxUnavailable: "100%"
  selector:
    matchLabels:
      k8s-app: cilium
      kubernetes.io/cluster-service: "true"
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
        scheduler.alpha.kubernetes.io/tolerations: >-
          [{"key":"dedicated","operator":"Equal","value":"master","effect":"NoSchedule"}]
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      serviceAccountName: cilium
      initContainers:
      - name: clean-cilium-state
        image: docker.io/library/busybox:1.28.4
        imagePullPolicy: IfNotPresent
        command: ['sh', '-c', 'if [ "${CLEAN_CILIUM_STATE}" = "true" ]; then rm -rf /var/run/cilium/state; rm -rf /sys/fs/bpf/tc/globals/cilium_*; fi']
        volumeMounts:
          - name: bpf-maps
            mountPath: /sys/fs/bpf
          - name: cilium-run
            mountPath: /var/run/cilium
        env:
          - name: "CLEAN_CILIUM_STATE"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                optional: true
                key: clean-cilium-state
      containers:
      - image: docker.io/cilium/cilium:__CILIUM_VERSION__
        imagePullPolicy: Always
        name: cilium-agent
        command: [ "cilium-agent" ]
        args:
          - "--debug=$(CILIUM_DEBUG)"
          - "--kvstore=etcd"
          - "--kvstore-opt=etcd.config=/var/lib/etcd-config/etcd.config"
          - "--disable-ipv4=$(DISABLE_IPV4)"
          - "--container-runtime=crio"
        ports:
          - name: prometheus
            containerPort: 9090
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
          - name: "CILIUM_DEBUG"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                key: debug
          - name: "DISABLE_IPV4"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                key: disable-ipv4
          # Note: this variable is a no-op if not defined, and is used in the
          # prometheus examples.
          - name: "CILIUM_PROMETHEUS_SERVE_ADDR"
            valueFrom:
              configMapKeyRef:
                name: cilium-metrics-config
                optional: true
                key: prometheus-serve-addr
          - name: "CILIUM_LEGACY_HOST_ALLOWS_WORLD"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                optional: true
                key: legacy-host-allows-world
          - name: CILIUM_TUNNEL
            valueFrom:
              configMapKeyRef:
                key: tunnel
                name: cilium-config
                optional: true
        livenessProbe:
          exec:
            command:
            - cilium
            - status
          # The initial delay for the liveness probe is intentionally large to
          # avoid an endless kill & restart cycle if in the event that the initial
          # bootstrapping takes longer than expected.
          initialDelaySeconds: 120
          failureThreshold: 10
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - cilium
            - status
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
          - name: bpf-maps
            mountPath: /sys/fs/bpf
          - name: cilium-run
            mountPath: /var/run/cilium
          - name: cni-path
            mountPath: /host/opt/cni/bin
          - name: etc-cni-netd
            mountPath: /host/etc/cni/net.d
          - name: crio-socket
            mountPath: /var/run/crio.sock
            readOnly: true
          - name: etcd-config-path
            mountPath: /var/lib/etcd-config
            readOnly: true
          - name: etcd-secrets
            mountPath: /var/lib/etcd-secrets
            readOnly: true
        securityContext:
          capabilities:
            add:
              - "NET_ADMIN"
          privileged: true
      hostNetwork: true
      volumes:
          # To keep state between restarts / upgrades
        - name: cilium-run
          hostPath:
            path: /var/run/cilium
          # To keep state between restarts / upgrades
        - name: bpf-maps
          hostPath:
            path: /sys/fs/bpf
          # To read labels from CRI-O containers running in the host
        - name: crio-socket
          hostPath:
            path: /var/run/crio.sock
          # To install cilium cni plugin in the host
        - name: cni-path
          hostPath:
            path: /opt/cni/bin
          # To install cilium cni configuration in the host
        - name: etc-cni-netd
          hostPath:
              path: /etc/cni/net.d
          # To read the etcd config stored in config maps
        - name: etcd-config-path
          configMap:
            name: cilium-config
            items:
            - key: etcd-config
              path: etcd.config
          # To read the k8s etcd secrets in case the user might want to use TLS
        - name: etcd-secrets
          secret:
            secretName: cilium-etcd-secrets
            optional: true
      restartPolicy: Always
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
      - effect: NoSchedule
        key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"
      # Mark cilium's pod as critical for rescheduling
      - key: CriticalAddonsOnly
        operator: "Exists"
