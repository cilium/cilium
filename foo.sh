function wait_for_cilium_api() {
    podname=${1}
    for i in $(seq 1 10); do
        echo "Waiting for Cilium API server to begin listening on cilium socket"
        if kubectl -n kube-system exec "${podname}" -- cilium status 2>/dev/null >/dev/null ; then
            echo "cilium status returned ok, proceeding"
            break
        else
            echo "status returned non-zero return, waiting 1 second before retrying..."
        fi
        sleep 1
    done
}

wait_for_cilium_api $(cagent)
