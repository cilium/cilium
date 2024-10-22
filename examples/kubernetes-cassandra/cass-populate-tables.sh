#!/usr/bin/env bash

CASS_SERVER_POD=$(kubectl get pods -l app=cass-server -o jsonpath='{.items[0].metadata.name}')

# create tables

kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"CREATE KEYSPACE deathstar WITH REPLICATION = { 'class' : 'NetworkTopologyStrategy', 'datacenter1' : 2 };\""
kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"CREATE TABLE deathstar.scrum_notes (creation timeuuid, empire_member_id uuid, content varchar, PRIMARY KEY (empire_member_id));\"" 

UUID1=`uuidgen`
UPDATE1="Trying to figure out if we should paint it medium grey, light grey, or medium-light grey.  Not blocked."
QUERY1="INSERT INTO deathstar.scrum_notes (empire_member_id, creation, content) values ($UUID1, now(), '${UPDATE1}');"
UUID2=`uuidgen`
UPDATE2="I think the exhaust port could be vulnerable to a direct hit.  Hope no one finds out about it.  Not blocked."
QUERY2="INSERT INTO deathstar.scrum_notes (empire_member_id, creation, content) values ($UUID2, now(), '${UPDATE2}');"
UUID3=`uuidgen`
UPDATE3="Designed protective shield for deathstar.  Could be based on nearby moon.  Feature punted to v2.  Not blocked."
QUERY3="INSERT INTO deathstar.scrum_notes (empire_member_id, creation, content) values ($UUID3, now(), '${UPDATE3}');"

kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"$QUERY1\""
kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"$QUERY2\""
kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"$QUERY3\""


kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"CREATE KEYSPACE attendance WITH REPLICATION = { 'class' : 'NetworkTopologyStrategy', 'datacenter1' : 2 };\""
kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"CREATE TABLE attendance.daily_records (creation timeuuid, loc_id uuid, present boolean, empire_member_id uuid, PRIMARY KEY (loc_id));\"" 

for i in `seq 0 10`; do
	mUUID=`uuidgen`
	lUUID=`uuidgen`
	kubectl exec $CASS_SERVER_POD -- sh -c "cqlsh -e \"INSERT INTO attendance.daily_records (creation, loc_id, present, empire_member_id) values (now(), $lUUID, true, $mUUID);\""
done
