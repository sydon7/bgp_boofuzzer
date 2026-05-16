# OpenBGPD — Kubernetes Deployment

This directory contains a Kubernetes Deployment manifest for running OpenBGPD as a fuzz target. The pod runs three containers: the OpenBGPD daemon, an RPKI client sidecar, and a health-exporter that runs the BooFuzz RPC monitor so the fuzzer can track whether the target process is alive.

## Pod layout

```
Pod: openbgpd1  (shareProcessNamespace: true)
├── openbgpd1     — OpenBGPD daemon (openbgpd/openbgpd:latest)
├── rpkiclient1   — RPKI client (rpki/rpki-client:latest)
└── health-exporter — BooFuzz RPC monitor (python:3.9-alpine, bootstrapped at startup)
```

`shareProcessNamespace: true` is set at the pod level. This is required so that the health-exporter container can use `pgrep` to see the OpenBGPD process running in the `openbgpd1` container.

## Container details

### `openbgpd1` container

- **Image:** `openbgpd/openbgpd:latest`
- **Ports:** 179/TCP (BGP), 9099/TCP (metrics)
- **Config mount:** `bgpd.conf` is loaded from the NFS PVC at subpath `conf/bgpd.conf`, mounted into the container at `/etc/bgpd/bgpd.conf`.
- **RPKI data mount:** `/var/lib/rpki-client` is mounted from subpath `rpki-client` on the PVC, giving OpenBGPD access to validated RPKI data produced by the rpkiclient sidecar.

### `rpkiclient1` container

- **Image:** `rpki/rpki-client:latest`
- Runs the RPKI client to fetch and validate Route Origin Authorizations (ROAs) from trust anchors.
- Writes validated output to `rpki-client/output` on the PVC (mounted at `/var/lib/rpki-client`).
- Caches downloaded data in `rpki-client/cache` on the PVC (mounted at `/var/cache/rpki-client`).
- OpenBGPD reads the validated output to enforce RPKI-based route filtering.

### `health-exporter` container

- **Image:** `python:3.9-alpine`
- **Port:** 1234/TCP — the BooFuzz RPC port the fuzzer connects to
- **Startup:** On launch, installs `procps` and `boofuzz`, writes the monitor script inline to `/tmp/health.py`, and starts the RPC server.
- **Monitor behaviour:** Uses `OPENBGPDMonitor`, which calls `pgrep -f 'bgpd -d -v'` every 2 seconds. When the process disappears it waits 5 seconds, then re-attaches. Like the FRR variant, it does **not** attempt to restart the daemon — Kubernetes handles recovery.

## Volume layout

All three containers share a single PVC (`nfs-pvc-openbgpd1`) with subpath mounts:

| Subpath on PVC | Mounted in | Mount path |
|---|---|---|
| `conf/bgpd.conf` | `openbgpd1` | `/etc/bgpd/bgpd.conf` |
| `rpki-client` | `openbgpd1` | `/var/lib/rpki-client` |
| `rpki-client/output` | `rpkiclient1` | `/var/lib/rpki-client` |
| `rpki-client/cache` | `rpkiclient1` | `/var/cache/rpki-client` |

Populate the PVC with at least a valid `conf/bgpd.conf` before deploying. The `rpki-client` subdirectory will be created by the RPKI client on first run.

## Prerequisites

- A Kubernetes namespace named `openbgpd1`:
  ```bash
  kubectl create namespace openbgpd1
  ```
- A PersistentVolumeClaim named `nfs-pvc-openbgpd1` in the `openbgpd1` namespace, with a valid `bgpd.conf` at subpath `conf/bgpd.conf`.

## Deploying

```bash
kubectl apply -f deployment.yaml
```

Verify all three containers are running:

```bash
kubectl get pods -n openbgpd1
kubectl logs -n openbgpd1 <pod-name> -c health-exporter
```

The health-exporter log should show:
```
Attached to [<PID>] -> bgpd -d -v
```

## Exposing the RPC port to the fuzzer

**NodePort service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: openbgpd1-monitor
  namespace: openbgpd1
spec:
  type: NodePort
  selector:
    app: openbgpd1
  ports:
  - name: rpc
    port: 1234
    targetPort: 1234
```

**Port-forward** (for ad-hoc testing):
```bash
kubectl port-forward -n openbgpd1 <pod-name> 1234:1234
```

## Running the fuzzer against this target

```bash
python fuzz_flowspec.py \
    --fbgp_id <FUZZER_IP> \
    --fasn <FUZZER_ASN> \
    --tip <OPENBGPD_POD_IP_OR_SERVICE_IP> \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspec_fuzz_profile1.yaml \
    --configfile bgp_defaults.yaml
```

Ensure the OpenBGPD configuration has the fuzzer's IP and ASN configured as a neighbor, otherwise the BGP OPEN will be rejected.

## OpenBGPD configuration notes

A minimal `bgpd.conf` to accept the fuzzer:

```
AS <OPENBGPD_ASN>
router-id <OPENBGPD_IP>

neighbor <FUZZER_IP> {
    remote-as <FUZZER_ASN>
    descr "bgp-boofuzzer"
}

# Allow flowspec routes from the fuzzer
flowspec { }
```

Place this file on the NFS volume at the path `conf/bgpd.conf` before deploying.
