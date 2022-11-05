function wait_for_svc_api() {
    # Attempt to get service list for ten seconds.
    # NOTE: Excessively long timeouts may indicate startup time regressions.
    podname=${1}
    for i in $(seq 1 30); do
        echo "Waiting for Cilium API server to begin listening on cilium socket"
        if SVC=$(kubectl -n kube-system exec "${podname}" -- cilium service list) ; then
            echo "cilium service list returned ok, proceeding"
            break
        else
            echo "'cilium service list' returned non-zero return, waiting 1 second before retrying..."
        fi
        sleep 1
    done
}

wait_for_svc_api "$(cagent)"
echo "done!"
