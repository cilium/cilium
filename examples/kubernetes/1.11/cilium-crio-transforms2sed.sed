# delete mounts
/        - mountPath: \/sys\/fs\/bpf/,+1 d
# delete volumes
/        # To keep state between restarts \/ upgrades for bpf maps/,+4 d
