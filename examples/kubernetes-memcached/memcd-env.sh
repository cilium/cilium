#!/usr/bin/env bash
#define ENV variables for memcached demo
MEMCD_SERVER_POD=$(kubectl get pods -l app=memcd-server -o jsonpath='{.items[0].metadata.name}')
AWING_POD=$(kubectl get pods -l app=a-wing -o jsonpath='{.items[0].metadata.name}')
XWING_POD=$(kubectl get pods -l app=x-wing -o jsonpath='{.items[0].metadata.name}')
TRACKER_POD=$(kubectl get pods -l name=fleet-tracker -o jsonpath='{.items[0].metadata.name}')
SETXC="set xwing-coord 0 2400 16\r\n8893.34,234.3290\r\nquit\r\n"
GETXC="get xwing-coord \r\nquit\r\n"
GETAC="get awing-coord \r\nquit\r\n"

echo "MEMCD_SERVER_POD=$(kubectl get pods -l app=memcd-server -o jsonpath='{.items[0].metadata.name}')"
echo "AWING_POD=$(kubectl get pods -l app=a-wing -o jsonpath='{.items[0].metadata.name}')"
echo "XWING_POD=$(kubectl get pods -l app=x-wing -o jsonpath='{.items[0].metadata.name}')"
echo "TRACKER_POD=$(kubectl get pods -l name=fleet-tracker -o jsonpath='{.items[0].metadata.name}')"
echo "SETXC=\"set xwing-coord 0 2400 16\\r\\n8893.34,234.3290\\r\\nquit\\r\\n\""
echo "GETXC=\"get xwing-coord \\r\\nquit\\r\\n\""
echo "GETAC=\"get awing-coord \\r\\nquit\\r\\n\""
