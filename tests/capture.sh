#!/bin/bash

# Start minikube
minikube start --memory=8192 --cpus=4

echo "Sleeping for 30 seconds..." && sleep 30

# Delete all workflow pods
kubectl delete --all pods --namespace=default

# Wait for minikube to be ready for demo
echo "Sleeping for 30 seconds..." && sleep 30

# Get IDs of workflow pods
OWNER_POD_ID="$(kubectl get pods | grep "owner" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"
ADDER_POD_ID="$(kubectl get pods | grep "adder" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"
MULTIPLIER_POD_ID="$(kubectl get pods | grep "multiplier" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"


# Start capturing on the eth0 interface of the tcpdump container of the owner pod
# -G SECONDS -W 1 : Run for SECONDS seconds
# -w FILE : specify the dump file
# -i INTERFACE : specify the interface
kubectl exec -it $OWNER_POD_ID -c tcpdump -- tcpdump -G 10 -W 1 -w /tmp/owner-cap-v1.pcap -i eth0 &


# While capture is running, POST request from owner to adder
echo "Sleeping for 3 seconds before POST..." && sleep 3
kubectl exec -it $OWNER_POD_ID -c workflow-owner -- curl --user owner:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "first_number": 4, "second_number": 7 }' 'http://adder:5000/api/adder'
echo "Sleeping for 15 seconds..." && sleep 15

# Copy capture to host machine
kubectl cp $OWNER_POD_ID:/tmp/owner-cap-v1.pcap -c tcpdump ~/owner.pcap

# Stop minikube
minikube stop
