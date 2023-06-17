#!/usr/bin/env bash


HQ_POD=$(kubectl get pods -l app=empire-hq -o jsonpath='{.items[0].metadata.name}')
OUTPOST_8888_POD=$(kubectl get pods -l outpostid=8888 -o jsonpath='{.items[0].metadata.name}')
OUTPOST_9999_POD=$(kubectl get pods -l outpostid=9999 -o jsonpath='{.items[0].metadata.name}')
BACKUP_POD=$(kubectl get pods -l app=empire-backup -o jsonpath='{.items[0].metadata.name}')

#generate traffic

echo "producing messages"
kubectl exec $HQ_POD sh -- -c "echo “Happy 40th Birthday to General Tagge” | ./kafka-produce.sh --topic empire-announce"
kubectl exec $HQ_POD sh -- -c "echo “deathstar plans v3” | ./kafka-produce.sh --topic deathstar-plans"

echo "consuming messages"

kubectl exec $OUTPOST_9999_POD sh -- -c "./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1"
kubectl exec $OUTPOST_8888_POD sh -- -c "./kafka-consume.sh --topic empire-announce --from-beginning --max-messages 1"
kubectl exec $BACKUP_POD sh -- -c "./kafka-consume.sh --topic deathstar-plans --from-beginning --max-messages 1"

