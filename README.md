# BGP BooFuzzer — Flowspec Fork

This is a fork of [bgp_boofuzzer](https://github.com/Northind/bgp_boofuzzer), a black-box BGP fuzzer built on [BooFuzz](https://boofuzz.readthedocs.io/en/stable/). The original tool is preserved (see [README_original.md](README_original.md)).

This fork adds **configuration-file-driven fuzzing** and a dedicated **BGP Flowspec (RFC 5575) fuzzer** that targets the `MP_REACH_NLRI` path attribute in BGP UPDATE messages.

---

## What's New

| Addition | Purpose |
|---|---|
| `fuzz_flowspec.py` | Flowspec NLRI fuzzer (dest/src prefix, protocol, ports) |
| `fuzz_flowspec_flags.py` | Flowspec NLRI fuzzer extended with TCP flags (type 9) |
| `utils/fuzz_utils.py` | Config-aware utility class that bridges YAML config and BooFuzz primitives |
| `bgp_defaults.yaml` | Default byte values for every packet field |
| `fuzz_configs/` | Fuzz profiles — per-field on/off switches for which fields to mutate |

---

## Concepts

### Config file (`bgp_defaults.yaml`)

Defines the **default byte value** for each named packet field. When a field is not being fuzzed it is emitted as a `s_static` using this value, keeping the packet otherwise well-formed.

```yaml
default_values:
    Origin Flags: "40"
    Origin Type Code: "01"
    AFI IPv4: "00 01"
    SAFI Labeled Unicast: "85"
    Destination prefix filter: "01"
    Destination Port: "00 03"
    # ...
```

Values are hex strings (spaces allowed). You can supply a different config file via `--configfile`.

### Fuzz profile (`fuzz_configs/*.yaml`)

Controls **which fields BooFuzz actually mutates**. Each field maps to `True` (fuzz it) or `False` (emit the default value unchanged).

```yaml
fuzzable:
    Origin Flags: False
    Destination prefix filter: True
    Destination prefix filter mask: True
    Protocal value: True
    # ...
```

Profiles let you target a specific slice of the packet without touching unrelated fields. Four profiles are included:

| File | What it fuzzes |
|---|---|
| `fuzz_configs/flowspec_fuzz_profile1.yaml` | Destination prefix (type 1), source prefix (type 2), protocol value, destination/source port type codes |
| `fuzz_configs/flowspec_fuzz_profile2.yaml` | Protocol value only |
| `fuzz_configs/flowspec_fuzz_config2.yaml` | Protocol value only (alternate baseline) |
| `fuzz_configs/flowspc_fuzz_default_false.yaml` | All fields `False` — sends a valid packet, useful for connectivity checks |

`fuzzfile.yaml` (project root) is a spare all-`False` profile you can copy and customise.

### How they interact

```
bgp_defaults.yaml          fuzz profile
       │                        │
       └──────── fuzz_utils ────┘
                     │
             BooFuzz primitives
          (s_static / s_byte / s_bytes)
```

`bgp_fuzz_utils_class` (in `utils/fuzz_utils.py`) reads both files at startup. For each named field it emits either:
- `s_static(value=<default>)` — when the profile marks the field `False`
- `s_byte` / `s_bytes(fuzzable=True)` — when the profile marks the field `True`

If no fuzz profile is supplied, every field that the script calls with `random_options=False` is emitted as `s_static`.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Running the Flowspec Fuzzer

### Basic syntax

```bash
python fuzz_flowspec.py \
    --fbgp_id <FUZZER_BGP_ID> \
    --fasn    <FUZZER_ASN> \
    --tip     <TARGET_IP> \
    --trpc_port <RPC_PORT> \
    --fuzzprofile <PROFILE_YAML> \
    [--configfile <DEFAULTS_YAML>]
```

`--configfile` defaults to `bgp_defaults.yaml` if omitted.

### Examples

Fuzz destination prefix, source prefix, and protocol fields:

```bash
python fuzz_flowspec.py \
    --fbgp_id 10.0.2.15 \
    --fasn 1234 \
    --tip 10.3.1.118 \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspec_fuzz_profile1.yaml \
    --configfile bgp_defaults.yaml
```

Fuzz only the protocol value:

```bash
python fuzz_flowspec.py \
    --fbgp_id 10.0.2.15 \
    --fasn 1234 \
    --tip 10.3.1.118 \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspec_fuzz_profile2.yaml
```

Send a baseline (unfuzzed) flowspec packet to verify connectivity:

```bash
python fuzz_flowspec.py \
    --fbgp_id 10.0.2.15 \
    --fasn 1234 \
    --tip 10.3.1.118 \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspc_fuzz_default_false.yaml
```

Fuzz TCP flags (type 9) in addition to the standard flowspec components:

```bash
python fuzz_flowspec_flags.py \
    --fbgp_id 10.0.2.15 \
    --fasn 1234 \
    --tip 10.3.1.118 \
    --trpc_port 1234 \
    --fuzzprofile fuzz_configs/flowspec_fuzz_profile1.yaml
```

---

## Packet Structure

Both `fuzz_flowspec.py` and `fuzz_flowspec_flags.py` build and send a three-message BGP session:

```
BGP OPEN  →  BGP KEEPALIVE  →  BGP UPDATE
```

The UPDATE contains:

```
BGP UPDATE
└── Path Attributes
    ├── ORIGIN
    ├── AS_PATH
    ├── LOCAL_PREF
    ├── EXTENDED_COMMUNITIES (rate-limit community)
    └── MP_REACH_NLRI  (AFI=1 / SAFI=133 flowspec)
        └── FLOW_SPEC_NLRI
            ├── Type 1 — Destination prefix
            ├── Type 2 — Source prefix
            ├── Type 3 — Protocol / next header
            ├── Type 5 — Destination port
            ├── Type 6 — Source port
            └── Type 9 — TCP flags  (fuzz_flowspec_flags.py only)
```

The OPEN message advertises both IPv4 unicast (AFI=1/SAFI=1) and IPv4 flowspec (AFI=1/SAFI=133) capabilities so the target will accept the flowspec UPDATE.

---

## Creating a Custom Fuzz Profile

1. Copy an existing profile:

   ```bash
   cp fuzz_configs/flowspc_fuzz_default_false.yaml fuzz_configs/my_profile.yaml
   ```

2. Set the fields you want to fuzz to `True`:

   ```yaml
   fuzzable:
       Destination prefix filter: True
       Destination prefix filter mask: True
       Destination prefix filter prefix: True
       # everything else stays False
   ```

3. Run with your profile:

   ```bash
   python fuzz_flowspec.py ... --fuzzprofile fuzz_configs/my_profile.yaml
   ```

Fields not listed in the profile default to **not fuzzed** (`False`).

---

## Crash Monitor (unchanged from upstream)

The optional RPC monitor (`myrpc.py`) watches the target process and generates a PoC script if it crashes. Supported targets: FRRouting, BIRD, OpenBGPD.

Start the monitor on the target machine:

```bash
python myrpc.py --ip <TARGET_IP> --port <RPC_PORT> --monitor [frr | bird | openbgpd]
```

See [README_original.md](README_original.md) for full monitor documentation and the `PoC/` directory for CVE-2022-40302 and CVE-2022-43681 reproduction scripts.

---

## Original Fuzz Scripts

The upstream fuzz scripts are still available and work as documented in [README_original.md](README_original.md):

| Script | Targets |
|---|---|
| `fuzz_open.py` | BGP OPEN message |
| `fuzz_update.py` | BGP UPDATE message |
| `fuzz_route_refresh.py` | BGP ROUTE REFRESH message |
| `fuzz_notification.py` | BGP NOTIFICATION message |
| `fuzz_baseline.py` | BGP UPDATE with NLRI prefix and extended group primitives |
