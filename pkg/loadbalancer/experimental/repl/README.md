A simple read-print-eval-loop for the load-balancer sub-system. This runs the load-balancing
control-plane with minimal dependencies allowing to explore its behavior, for example for
preparing a new testcase (testdata/foo.txtar). The same commands are also available via
"cilium-dbg shell" for inspecting a live system.

If `--k8s-kubeconfig-path` is specified the real k8s client is used. Without it one can
insert Kubernetes objects using the fake client's `k8s add` command.

Example session:

    $ go run . --k8s-kubeconfig-path ~/.kube/config
    loadbalancer> hive start
    time=2024-12-12T14:50:05.406+01:00 level=INFO msg="Starting hive"
    time=2024-12-12T14:50:05.406+01:00 level=INFO msg=Started duration=240.865µs
    ...
    loadbalancer> db/show services
    [stdout]
    Name                      Source   NatPolicy   ExtTrafficPolicy   IntTrafficPolicy   SessionAffinity   ProxyRedirect   HealthCheckNodePort   LoopbackHostPort   SourceRanges
    default/kubernetes        k8s                  Cluster            Cluster                                              0                     false
    kube-system/hubble-peer   k8s                  Cluster            Local                                                0                     false
    kube-system/kube-dns      k8s                  Cluster            Cluster                                              0                     false
    loadbalancer> db/show frontends
    [stdout]
    Address                 Type        ServiceName               PortName       Backends                                                        Status   Since   Error
    10.96.0.1:443/TCP       ClusterIP   default/kubernetes        https          172.18.0.2:6443/TCP (active)                                    Done     42s
    10.96.0.10:53/TCP       ClusterIP   kube-system/kube-dns      dns-tcp        10.244.1.56:53/TCP (active), 10.244.1.223:53/TCP (active)       Done     42s
    10.96.0.10:53/UDP       ClusterIP   kube-system/kube-dns      dns            10.244.1.56:53/UDP (active), 10.244.1.223:53/UDP (active)       Done     42s
    10.96.0.10:9153/TCP     ClusterIP   kube-system/kube-dns      metrics        10.244.1.56:9153/TCP (active), 10.244.1.223:9153/TCP (active)   Done     42s
    10.96.136.131:443/TCP   ClusterIP   kube-system/hubble-peer   peer-service   172.18.0.2:4244/TCP (active), 172.18.0.3:4244/TCP (active)      Done     42s
    loadbalancer> db/show backends
    [stdout]
    Address                 State    Instances                                  Shadows                       NodeName             ZoneID
    10.244.1.56:53/TCP      active   kube-system/kube-dns (dns-tcp)             kube-system/kube-dns []       kind-worker          0
    10.244.1.56:53/UDP      active   kube-system/kube-dns (dns)                 kube-system/kube-dns []       kind-worker          0
    10.244.1.56:9153/TCP    active   kube-system/kube-dns (metrics)             kube-system/kube-dns []       kind-worker          0
    ...
    loadbalancer> lb/maps-dump
    [stdout]
    BE: ID=1 ADDR=10.244.1.56:53/UDP STATE=active
    ...
    REV: ID=1 ADDR=10.96.0.10:53
    ...
    SVC: ID=5 ADDR=10.96.136.131:443/TCP SLOT=2 BEID=9 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+InternalLocal+non-routable

When run as non-root it uses in-memory mock BPF maps and when run as root
it will use unpinned BPF maps, allowing you to populate and inspect the load-balancer
BPF maps:

    $ go build .
    $ sudo ./repl --k8s-kubeconfig-path ~/.kube/config
    loadbalancer> hive start
    ^Z
    $ sudo bpftool map dump name cilium_lb4_serv
    key: 0a 00 00 01 04 d2 00 00  06 00 00 00  value: 00 00 00 00 00 00 00 01  00 00 00 00
    Found 1 element

The standalone load-balancing can be experimented with using:

    $ go run repl --lb-local-sync-file repl/example.yaml
    loadbalancer> hive start
    loadbalancer> db/show frontends
    Address           Type           ServiceName   PortName   Backends                                                                            Status   Since   Error
    10.0.0.1:80/TCP   LoadBalancer   test/svc1                10.1.0.1:80/TCP (active)                                                            Done     7s
    10.0.0.2:80/TCP   LoadBalancer   test/svc2                10.1.0.2:80/TCP (active), 10.1.0.3:80/TCP (active), 10.1.0.4:80/TCP (maintenance)   Done     7s

Try modifying `repl/example.yaml` to update the state.
