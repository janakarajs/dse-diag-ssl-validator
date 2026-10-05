# DSE Diagnostic Bundle Internode SSL Validator

A standalone Python validator for checking and comparing **Internode SSL/TLS health** across DSE / Apache Cassandra cluster nodes directly from an unpacked diagnostic bundle (`proddsecluster-diagnostics-*.tar.gz`).

Designed specifically for support engineers, DBAs, and SREs to run on local jump boxes, diagnostic servers, or ECU/support repositories **without needing SSH credentials or direct connectivity to customer environments**.

---

## Supported Versions
* **DataStax Enterprise (DSE):** 5.1, 6.7, 6.8, 6.9
* **Apache Cassandra:** 3.11, 4.0+

---

## Requirements

* **Python:** 3.8+
* **Dependencies:** `PyYAML`

```bash
pip install pyyaml
```

---

## Installation

```bash
git clone https://github.com/janakarajs/dse-diag-ssl-validator.git
cd dse-diag-ssl-validator
pip install pyyaml
```

---

## Usage

```bash
# Basic usage — pass the root path of the unpacked diagnostic bundle
python3 diag_internode_validator.py --bundle-dir /path/to/unpacked-diagnostics/

# Example on support/jump server
python3 diag_internode_validator.py \
  --bundle-dir /ecurep/sf/TS023/054/TS023054434/2026-10-05/diagnostics_1_.tar.gz_unpack/proddsecluster-diagnostics-2026_10_05_07_11_52_UTC/

# Disable ANSI colors (useful for CI/CD logs or piping to text files)
python3 diag_internode_validator.py --bundle-dir /path/to/bundle --no-color
```

---

## What is Validated

### 1. Per-Node `server_encryption_options` Audit
* **`internode_encryption` setting**: Verifies that internode encryption is enabled (`all`, `dc`, `rack`) and fails if set to `none`.
* **Path configuration**: Checks keystore and truststore path specifications.
* **Protocol compliance**: Flags deprecated protocols (`SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`) and validates `TLS` configuration.
* **Authentication mode**: Identifies whether the cluster operates in **1-way SSL** or **2-way mTLS** (`require_client_auth`).
* **Endpoint verification**: Checks `require_endpoint_verification` status and hostname/SAN enforcement.
* **Cipher suites**: Audits configured cipher suites or JVM default usage.

### 2. Cluster-Wide Consistency & Cross-Node Comparison
* **Encryption mode consistency**: Ensures all nodes agree on `internode_encryption` (`all` vs `dc` vs `none`).
* **Protocol alignment**: Verifies identical SSL/TLS protocols across all nodes.
* **Client authentication consistency**: Flags dangerous mismatches where some nodes require client certificates while others do not.
* **Storage port agreement**: Compares `STORAGE_PORT_SSL` from gossip (`7000` vs `7001`).
* **Cipher suite overlap**: Checks for common cipher suite intersections across nodes.
* **Schema agreement**: Compares schema IDs across all nodes in gossip to verify cluster synchronization.

### 3. Log-Based Runtime Exception & PKIX Scanner (Historical vs. Active Disambiguation)
* Scans `system.log`, `output.log`, and `debug.log` across all nodes for SSL events (`SSLHandshakeException`, `certificate_unknown`, `unknown_ca`, `PKIX path building failed`).
* **Distinguishes Historical/Transient vs Active Failures**: Cross-references handshake errors with `nodetool netstats` and `nodetool info`. If millions of encrypted small/gossip messages are successfully completed, past log errors during rolling cert rotations are marked as **`(Historical/Resolved)`** with a `[WARN]` rather than a false positive `[FAIL]`.

### 4. DSE Service Restart & Keystore Rotation Audit
* **Process Start & Uptime Extraction**: Determines exact process startup time and node uptime from `CassandraDaemon` startup logs and `nodetool/info`.
* **Dynamic Truststore Reload Verification**: Confirms if `DseServerReloadableTrustManager` picked up updated truststores.
* **Unapplied Keystore Rotation Alert**: Flags long-running nodes experiencing SSL handshake failures without a DSE service restart (since DSE does not dynamically reload `server.keystore` from disk; an explicit rolling restart is required).

---

## Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | **PASS** — All internode SSL checks passed cleanly. |
| `1` | **WARN** — Warnings detected (e.g. schema migration in progress, unencrypted optional fallback enabled). |
| `2` | **FAIL** — Critical failure detected (disabled SSL, fatal handshake alerts, config mismatch). |

---

## License
MIT License
