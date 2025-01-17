A simple read-print-eval loop for the load-balancer sub-system.


Example session:

    $ go run .
    loadbalancer> hive start
    time=2024-12-12T14:50:05.406+01:00 level=INFO msg="Starting hive"
    time=2024-12-12T14:50:05.406+01:00 level=INFO msg=Started duration=240.865µs
    loadbalancer> lb/service default/test
    Added service "default/test"
    loadbalancer> lb/frontend default/test 1.2.3.4:80/TCP
    Added frontend "1.2.3.4:80/TCP"
    loadbalancer> lb/backend default/test 2.3.4.5:8888/TCP
    Upserted backends [{2.3.4.5 {TCP 8888} 0}]
    loadbalancer> db/show frontends
    Address          Type        ServiceName    PortName   Backends                    Status   Since   Error
    1.2.3.4:80/TCP   ClusterIP   default/test              2.3.4.5:8888/TCP (active)   Done     10s
    loadbalancer> lb/maps-dump
    BE: ID=1 ADDR=2.3.4.5:8888/TCP STATE=active
    REV: ID=1 ADDR=1.2.3.4:80
    SVC: ID=1 ADDR=1.2.3.4:80/TCP SLOT=0 BEID=0 COUNT=1 QCOUNT=0 FLAGS=ClusterIP+non-routable
    SVC: ID=1 ADDR=1.2.3.4:80/TCP SLOT=1 BEID=1 COUNT=0 QCOUNT=0 FLAGS=ClusterIP+non-routable

When run as non-root it uses in-memory mock BPF maps and when run as root
it will use unpinned BPF maps, allowing you to populate and inspect the load-balancer
BPF maps:

    $ go build .
    $ sudo ./repl
    loadbalancer> hive start
    loadbalancer> lb/service default/test
    loadbalancer> lb/frontend default/test 10.0.0.1:80/TCP
    ^Z
    $ sudo bpftool map dump name cilium_lb4_serv
    key: 0a 00 00 01 04 d2 00 00  06 00 00 00  value: 00 00 00 00 00 00 00 01  00 00 00 00
    Found 1 element
