# Proof of Concept

This repository contains the code to deploy and test our proof of concept.

The `services` folder contains the services we want to deploy inside our infrastructure.
The `containerized-services` folder contains those same services, containerized.
The `service-mesh` folder contains YAML deployment files for the infrastructure.
The `tests` folder contains our testing framework with accompanying packet captures.

The proof of concept has been realized with `minikube` v1.8.1, `Kubernetes` v1.17.3, `Istio` v.1.5.0 and Open Policy Agent.



# Installation

## Prerequisites

Check if virtualization is supported.
On Linux, run `grep -E --color 'vmx|svm' /proc/cpuinfo`.


## Kubernetes

1. Download and install the latest release of `kubectl`.

```sh
curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl

chmod +x ./kubectl

sudo mv ./kubectl /usr/local/bin/kubectl
```

2. Install `minikube`.

```sh
curl -Lo minikube https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 \
  && chmod +x minikube

sudo mkdir -p /usr/local/bin/
sudo install minikube /usr/local/bin/
```

3. Start `minikube` with a profile and resources.

```sh
minikube start --cpus=4 --memory=8192 -p "proof-of-concept"
```


## Istio

1. Download `Istio`.

```sh
curl -L https://istio.io/downloadIstio | sh -

cd istio-1.5.0
export PATH=$PWD/bin:$PATH
```

2. Install `Istio`.

```sh
istioctl manifest apply --set profile=demo

kubectl label namespace default istio-injection=enabled
```

3. Enforce `mTLS` communications

```sh
kubectl apply -n istio-system -f - <<EOF
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
spec:
  mtls:
    mode: STRICT
EOF
```


## Open Policy Agent

1. Install the `OPA-Istio` CRDs and our custom policy.

```sh
kubectl apply -f service-mesh/policy.yaml
```

2. Enable automatic injection of the OPA sidecars for services of the workflow.

```sh
kubectl label namespace default opa-istio-injection="enabled"
```


## Deploying the workflow

1. Use the `Docker` registry of `minikube`.

```sh
eval $(minikube docker-env)
```

2. Build the service images

```sh
docker build -t adder:latest containerized-services/workflow-adder
docker build -t multiplier:latest containerized-services/workflow-multiplier
docker build -t owner:latest containerized-services/workflow-owner
```

3. Check if the images were built sucessfully

```sh
minikube ssh docker images
```

4. Deploy the workflow

```sh
kubectl apply -f service-mesh/workflow-deployment.yaml
```



# Using the proof of concept

IDs of pods can be retrived with the following:

```sh
OWNER_POD_ID="$(kubectl get pods | grep "owner" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"
ADDER_POD_ID="$(kubectl get pods | grep "adder" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"
MULTIPLIER_POD_ID="$(kubectl get pods | grep "multiplier" | tr -s ' ' | cut -d ' ' -f 1 | awk 'NR>1{print PREV} {PREV=$0} END{printf("%s",$0)}')"
```

Some requests can be made with the following:

```sh
# POST request from the owner to the adder
kubectl exec -it $OWNER_POD_ID -c workflow-owner -- curl --user owner:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "first_number": 4, "second_number": 7 }' 'http://adder:5000/api/adder'

# POST request from the owner to the multiplier
kubectl exec -it $OWNER_POD_ID -c workflow-owner -- curl --user owner:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "first_number": 4, "second_number": 7 }' 'http://multiplier:5001/api/multiplier'


# POST request from the adder to the multiplier
kubectl exec -it $ADDER_POD_ID -c workflow-adder -- curl --user adder:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "first_number": 4, "second_number": 7 }' 'http://multiplier:5001/api/multiplier'

# POST request from the adder to the owner
kubectl exec -it $ADDER_POD_ID -c workflow-adder -- curl --user adder:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "result": 4 }' 'http://owner:5002/api/owner'


# POST request from the multiplier to the adder
kubectl exec -it $MULTIPLIER_POD_ID -c workflow-multiplier -- curl --user multiplier:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "first_number": 4, "second_number": 7 }' 'http://adder:5000/api/adder'

# POST request from the multiplier to the owner
kubectl exec -it $MULTIPLIER_POD_ID -c workflow-multiplier -- curl --user multiplier:password -X POST --header 'Content-Type: application/json' --header 'Accept: text/html' -d '{ "result": 4 }' 'http://owner:5002/api/owner'
```



# Testing the proof of concept

Our proof of concept can be tested with the following:

```sh
python tests/tests.py


usage: tests.py [-h] [--version] [-v] [-q] [-s] [-n] [-p FILE] [-d DIR]
                [-o NAME:IP...] [-k]

Tests for secure architecture

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         increase output verbosity
  -q, --quiet           hide command outputs
  -s, --start           initialize Kubernetes for tests
  -n, --no-capture      do not capture
  -p FILE, --policy-file FILE
                        policy file for capture checking
  -d DIR, --capture-dir DIR
                        packet capture folder
  -o NAME:IP..., --override-pods NAME:IP...
                        override pod IP addresses
  -k, --kill            stop Kubernetes before terminating program

```
