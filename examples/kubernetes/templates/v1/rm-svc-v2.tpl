        - name: rm-cilium-svc-v2
          image: docker.io/cilium/cilium:__CILIUM_VERSION__
          imagePullPolicy: IfNotPresent
          command: ["/bin/bash"]
          args:
          - -c
          - "rm /sys/fs/bpf/tc/globals/cilium_lb{4,6}_{services_v2,backends,rr_seq_v2}; true"
          volumeMounts:
          - mountPath: /sys/fs/bpf
            name: bpf-maps
