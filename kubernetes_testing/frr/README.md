# FRRouting — Kubernetes Deployment

This directory contains a Kubernetes Deployment manifest for running FRRouting (FRR) as a fuzz target. The pod pairs the FRR BGP daemon with a sidecar health-exporter container that runs the BooFuzz RPC monitor, allowing the fuzzer to track whether the target is alive across test cases.

## Pod layout

```
Pod: frr2
├── frr             — FRRouting BGP daemon (quay.io/frrouting/frr:10.5.0)
└── health-exporter — BooFuzz RPC monitor (python:3.9-alpine, bootstrapped at startup)
```

### `frr` container

- **Image:** `quay.io/frrouting/frr:10.5.0`
- **Ports:** 179/TCP (BGP), 2601/TCP, 2605/TCP
- **Capabilities:** `NET_ADMIN`, `SYS_ADMIN` — required for FRR to manage routing tables and raw sockets
- **Config mount:** `/etc/frr` is mounted from the PVC `nfs-pvc-frr2`. Place your `frr.conf`, `bgpd.conf`, `daemons`, and `vtysh.conf` files there before deploying.

### `health-exporter` container

- **Image:** `python:3.9-alpine`
- **Port:** 1234/TCP — the BooFuzz RPC port the fuzzer connects to
- **Startup:** On launch, the container installs `procps` and `boofuzz`, writes `myrpc_kube.py` inline to `/tmp/health.py`, and starts the RPC server.
- **Monitor behaviour:** Uses `FRRMonitor`, which calls `pgrep -f /usr/lib/frr/bgpd` every 2 seconds to check if the daemon is running. When the process disappears it waits 20 seconds (to allow Kubernetes to restart the pod/container) and then re-attaches. The monitor does **not** attempt to stop or restart FRR itself — that is delegated to Kubernetes.

## Prerequisites

- A Kubernetes namespace named `frr2`:
  ```bash
  kubectl create namespace frr2
  ```
- A PersistentVolumeClaim named `nfs-pvc-frr2` in the `frr2` namespace backed by an NFS (or other) volume. The volume must contain a valid FRR configuration at its root (e.g., `frr.conf`, `daemons`).

## Deploying

```bash
kubectl apply -f deployment.yaml
```

Verify the pod is running:

```bash
kubectl get pods -n frr2
kubectl logs -n frr2 <pod-name> -c health-exporter
```

The health-exporter log should show a line like:
```
Attached to [<PID>] -> /usr/lib/frr/bgpd
```

## Exposing the RPC port to the fuzzer

The fuzzer needs to reach port 1234 on the health-exporter. Options:

**NodePort service** (simplest):
```yaml
apiVersion: v1
kind: Service
metadata:
  name: frr2-monitor
  namespace: frr2
spec:
  type: NodePort
  selector:
    app: frr2
  ports:
  - name: rpc
    port: 1234
    targetPort: 1234
```

**Port-forward** (for ad-hoc testing):
```bash
kubectl port-forward -n frr2 <pod-name> 1234:1234
```

## Running the fuzzer against this target

Once the RPC port is reachable, run the fuzzer from the machine where the fuzzer lives:

```bash
python fuzz_flowspec.py \
    --fbgp_id <FUZZER_IP> \
    --fasn <FUZZER_ASN> \
    --tip <FRR_POD_IP_OR_SERVICE_IP> \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspec_fuzz_profile1.yaml \
    --configfile bgp_defaults.yaml
```

Make sure the FRR BGP configuration accepts a peer with the fuzzer's IP and ASN, otherwise the OPEN handshake will be rejected before any UPDATE messages are sent.

## FRR configuration notes

A minimal `bgpd.conf` entry to accept the fuzzer as a peer:

```
router bgp <FRR_ASN>
 bgp router-id <FRR_IP>
 neighbor <FUZZER_IP> remote-as <FUZZER_ASN>
 neighbor <FUZZER_IP> description bgp-boofuzzer
 !
 address-family ipv4 flowspec
  neighbor <FUZZER_IP> activate
 exit-address-family
```

The `daemons` file must have `bgpd=yes` for the BGP daemon to start.
