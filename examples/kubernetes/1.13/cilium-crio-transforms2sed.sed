# delete mounts
/            - name: bpf-maps/,+1 d
# delete volumes
/        # To keep state between restarts \/ upgrades for bpf maps/,+4 d
