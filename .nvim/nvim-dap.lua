local dap = require('dap')

dap.adapters.cilium_kind_control_plane_1 = {
    type = "server",
    host = "127.0.0.1",
    port = 23401,
}
dap.adapters.cilium_kind_worker_1 = {
    type = "server",
    host = "127.0.0.1",
    port = 23411
}
dap.adapters.cilium_kind_worker_2 = {
    type = "server",
    host = "127.0.0.1",
    port = 23412
}
dap.adapters.cilium_operator_kind_worker_1 = {
    type = "server",
    host = "127.0.0.1",
    port = 23511
}
dap.configurations.go = {
    {
        type = "cilium_kind_control_plane_1",
        request = "attach",
        name = "Attach to kind-control-plane-1",
        mode = "remote",
        substitutePath = {
            {
                from = "${workspaceFolder}",
                to = "/go/src/github.com/cilium/cilium"
            }
        }
    },
    {
        type = "cilium_kind_worker_1",
        request = "attach",
        name = "Attach to kind-worker-1",
        mode = "remote",
        substitutePath = {
            {
                from = "${workspaceFolder}",
                to = "/go/src/github.com/cilium/cilium"
            }
        }
    },
    {
        type = "cilium_kind_worker_2",
        request = "attach",
        name = "Attach to kind-worker-2",
        mode = "remote",
        substitutePath = {
            {
                from = "${workspaceFolder}",
                to = "/go/src/github.com/cilium/cilium"
            }
        }
    },
    {
        type = "cilium_operator_kind_worker_1",
        request = "attach",
        name = "Attach to Cilium Operator",
        mode = "remote",
        substitutePath = {
            {
                from = "${workspaceFolder}",
                to = "/go/src/github.com/cilium/cilium"
            }
        }
    }
}
