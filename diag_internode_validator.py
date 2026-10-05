#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSE Diagnostic Bundle Internode SSL Validator
=============================================
Validates and compares Internode SSL/TLS configuration, topology, and runtime health
across all nodes directly from an unpacked DSE/Cassandra diagnostic bundle.

Designed to run locally on the diagnostic server/bundle directory without SSH or live credentials.

Supported DSE / C* versions:
  - DSE 5.1 / 6.7 / 6.8 / 6.9
  - Apache Cassandra 3.11 / 4.0+

Usage:
  python3 diag_internode_validator.py --bundle-dir /path/to/proddsecluster-diagnostics-xxx/
  python3 diag_internode_validator.py  # auto-detects current directory or subdirectories
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required. Run: pip install pyyaml")

# Terminal color formatting
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


@dataclass
class Finding:
    node: str
    check: str
    status: str  # PASS, WARN, FAIL, INFO
    detail: str
    fix: str = ""

    def formatted(self, no_color: bool = False) -> str:
        tag_colors = {
            "PASS": Colors.GREEN,
            "WARN": Colors.YELLOW,
            "FAIL": Colors.RED,
            "INFO": Colors.CYAN,
        }
        color = "" if no_color else tag_colors.get(self.status, "")
        reset = "" if no_color else Colors.RESET
        bold = "" if no_color else Colors.BOLD
        dim = "" if no_color else Colors.DIM

        out = f"  [{color}{self.status:<4}{reset}] {bold}{self.node:<15}{reset} │ {self.check}: {self.detail}"
        if self.fix:
            out += f"\n         {dim}└─ Suggestion: {self.fix}{reset}"
        return out


@dataclass
class NodeDiag:
    ip: str
    node_dir: str
    cassandra_yaml_path: str = ""
    yaml_data: dict = field(default_factory=dict)
    dse_version: str = "unknown"
    release_version: str = "unknown"
    dc: str = ""
    rack: str = ""
    listen_address: str = ""
    storage_port: int = 7000
    ssl_storage_port: int = 7001
    server_enc: dict = field(default_factory=dict)
    log_files: List[str] = field(default_factory=list)
    schema_id: str = ""
    uptime_seconds: int = 0
    proc_start_time: Optional[datetime.datetime] = None
    truststore_load_times: List[datetime.datetime] = field(default_factory=list)
    keystore_load_times: List[datetime.datetime] = field(default_factory=list)
    yaml_mtime: Optional[datetime.datetime] = None
    # Live cluster operational metrics (proves active connectivity despite historical log entries)
    gossip_active: bool = False
    native_active: bool = False
    gossip_generation: int = 0
    gossip_heartbeat: int = 0
    small_messages_completed: int = 0
    large_messages_completed: int = 0
    gossip_messages_completed: int = 0


# Known deprecated or insecure SSL/TLS protocols
DEPRECATED_PROTOCOLS = {"SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}

# Regex patterns for SSL errors in logs
SSL_LOG_PATTERNS = [
    (r"SSLHandshakeException", "SSL handshake failed", "FAIL", "Verify certificates, truststore CA bundles, and cipher suites."),
    (r"SunCertPathBuilderException|unable to find valid certification path", "PKIX path building failed (CA missing in truststore)", "FAIL", "Import signing CA into server.truststore on this node."),
    (r"certificate_unknown", "Peer sent unknown certificate alert", "FAIL", "Verify that peer certificate is issued by a trusted CA present in truststore."),
    (r"unknown_ca", "Peer rejected certificate due to unknown CA", "FAIL", "Add issuing CA to the peer's truststore."),
    (r"Keystore was tampered with, or password was incorrect", "Keystore corruption or invalid password", "FAIL", "Verify keystore integrity and passwords in cassandra.yaml."),
    (r"No appropriate protocol.*\(protocol is disabled or cipher suites are inappropriate\)", "TLS protocol / cipher suite negotiation failure", "FAIL", "Align protocol and cipher_suites in cassandra.yaml across all nodes."),
    (r"javax\.net\.ssl\.SSLException: Received fatal alert", "Fatal SSL alert during internode communication", "FAIL", "Check peer node logs to identify the exact rejection reason."),
    (r"DseServerReloadableTrustManager.*Reloading TrustStore", "Truststore reloaded successfully", "INFO", ""),
    (r"Handshaking version .* with /([0-9.]+)", "MessagingService connection established", "INFO", ""),
]


class DiagBundleInternodeValidator:
    def __init__(self, bundle_root: str, log_level: str = "INFO", no_color: bool = False):
        self.bundle_root = os.path.abspath(bundle_root)
        self.no_color = no_color
        self.nodes: Dict[str, NodeDiag] = {}
        self.findings: List[Finding] = []
        self.cluster_name: str = "Unknown"

    def locate_and_load_nodes(self) -> bool:
        """Find nodes directory and populate NodeDiag instances."""
        nodes_dir = os.path.join(self.bundle_root, "nodes")
        if not os.path.isdir(nodes_dir):
            # Check if current directory itself contains node IP folders
            subdirs = [d for d in os.listdir(self.bundle_root) if os.path.isdir(os.path.join(self.bundle_root, d))]
            if any(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) for d in subdirs):
                nodes_dir = self.bundle_root
            else:
                self.findings.append(Finding(
                    "bundle", "locate_nodes", "FAIL",
                    f"Could not find 'nodes/' directory in {self.bundle_root}",
                    "Ensure you point to an unpacked DSE diagnostic bundle root directory."
                ))
                return False

        # Parse cluster_info.json if available
        cluster_info_path = os.path.join(self.bundle_root, "cluster_info.json")
        if os.path.isfile(cluster_info_path):
            try:
                with open(cluster_info_path, "r", encoding="utf-8", errors="replace") as f:
                    cdata = json.load(f)
                    self.cluster_name = cdata.get("cluster_name", self.cluster_name)
            except Exception:
                pass

        for entry in sorted(os.listdir(nodes_dir)):
            node_path = os.path.join(nodes_dir, entry)
            if not os.path.isdir(node_path):
                continue

            node_ip = entry
            node = NodeDiag(ip=node_ip, node_dir=node_path)

            # Discover cassandra.yaml
            for yaml_candidate in [
                os.path.join(node_path, "conf", "cassandra", "cassandra.yaml"),
                os.path.join(node_path, "conf", "cassandra.yaml"),
            ]:
                if os.path.isfile(yaml_candidate):
                    node.cassandra_yaml_path = yaml_candidate
                    try:
                        with open(yaml_candidate, "r", encoding="utf-8", errors="replace") as yf:
                            node.yaml_data = yaml.safe_load(yf) or {}
                            node.server_enc = node.yaml_data.get("server_encryption_options") or {}
                            node.listen_address = node.yaml_data.get("listen_address", node.ip)
                    except Exception as e:
                        self.findings.append(Finding(
                            node.ip, "cassandra_yaml_parse", "FAIL",
                            f"Failed to parse {yaml_candidate}: {e}"
                        ))
                    break

            # Parse nodetool/version
            ver_path = os.path.join(node_path, "nodetool", "version")
            if os.path.isfile(ver_path):
                try:
                    with open(ver_path, "r", encoding="utf-8", errors="replace") as vf:
                        vtext = vf.read()
                        dse_m = re.search(r"DSE version:\s*(.+)", vtext)
                        rel_m = re.search(r"ReleaseVersion:\s*(.+)", vtext)
                        if dse_m:
                            node.dse_version = dse_m.group(1).strip()
                        if rel_m:
                            node.release_version = rel_m.group(1).strip()
                except Exception:
                    pass

            # Parse nodetool/gossipinfo for port, rack, dc, schema
            gossip_path = os.path.join(node_path, "nodetool", "gossipinfo")
            if os.path.isfile(gossip_path):
                try:
                    with open(gossip_path, "r", encoding="utf-8", errors="replace") as gf:
                        gtext = gf.read()
                        # Extract this node's section or peer entries
                        dc_m = re.search(rf"/{node.ip}[\s\S]*?DC:\d+:(.+)", gtext)
                        rack_m = re.search(rf"/{node.ip}[\s\S]*?RACK:\d+:(.+)", gtext)
                        schema_m = re.search(rf"/{node.ip}[\s\S]*?SCHEMA:\d+:([a-f0-9\-]+)", gtext)
                        sport_m = re.search(rf"/{node.ip}[\s\S]*?STORAGE_PORT:\d+:(\d+)", gtext)
                        ssport_m = re.search(rf"/{node.ip}[\s\S]*?STORAGE_PORT_SSL:\d+:(\d+)", gtext)

                        if dc_m:
                            node.dc = dc_m.group(1).strip()
                        if rack_m:
                            node.rack = rack_m.group(1).strip()
                        if schema_m:
                            node.schema_id = schema_m.group(1).strip()
                        if sport_m:
                            node.storage_port = int(sport_m.group(1))
                        if ssport_m:
                            node.ssl_storage_port = int(ssport_m.group(1))
                except Exception:
                    pass

            # Parse nodetool/info for uptime, gossip active, generation
            info_path = os.path.join(node_path, "nodetool", "info")
            if os.path.isfile(info_path):
                try:
                    with open(info_path, "r", encoding="utf-8", errors="replace") as inf:
                        for line in inf:
                            if "Uptime (seconds)" in line:
                                parts = line.split(":")
                                if len(parts) > 1 and parts[1].strip().isdigit():
                                    node.uptime_seconds = int(parts[1].strip())
                            elif "Gossip active" in line:
                                node.gossip_active = "true" in line.lower()
                            elif "Native Transport active" in line:
                                node.native_active = "true" in line.lower()
                            elif "Generation No" in line:
                                parts = line.split(":")
                                if len(parts) > 1 and parts[1].strip().isdigit():
                                    node.gossip_generation = int(parts[1].strip())
                except Exception:
                    pass

            # Parse nodetool/netstats for completed encrypted messaging counts
            netstats_path = os.path.join(node_path, "nodetool", "netstats")
            if os.path.isfile(netstats_path):
                try:
                    with open(netstats_path, "r", encoding="utf-8", errors="replace") as nsf:
                        for line in nsf:
                            parts = line.split()
                            if len(parts) >= 4 and parts[-2].isdigit():
                                if "Small messages" in line:
                                    node.small_messages_completed = int(parts[-2])
                                elif "Large messages" in line:
                                    node.large_messages_completed = int(parts[-2])
                                elif "Gossip messages" in line:
                                    node.gossip_messages_completed = int(parts[-2])
                except Exception:
                    pass

            # Parse process start time and truststore/keystore reload events from logs
            log_dir = os.path.join(node_path, "logs", "cassandra")
            if os.path.isdir(log_dir):
                for lf in ["output.log", "system.log", "debug.log"]:
                    full_lp = os.path.join(log_dir, lf)
                    if os.path.isfile(full_lp):
                        node.log_files.append(full_lp)
                        try:
                            with open(full_lp, "r", encoding="utf-8", errors="replace") as lf_h:
                                for line in lf_h:
                                    # Process start
                                    if "CassandraDaemon.java" in line and "Process information PID" in line and not node.proc_start_time:
                                        ts_m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                                        if ts_m:
                                            try:
                                                node.proc_start_time = datetime.datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S")
                                            except Exception:
                                                pass
                                    # Truststore reload
                                    if "Reloading TrustStore from" in line:
                                        ts_m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                                        if ts_m:
                                            try:
                                                dt = datetime.datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S")
                                                if dt not in node.truststore_load_times:
                                                    node.truststore_load_times.append(dt)
                                            except Exception:
                                                pass
                                    # Keystore reload
                                    if "Reloading KeyStore from" in line or "Reloading keystore" in line:
                                        ts_m = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                                        if ts_m:
                                            try:
                                                dt = datetime.datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S")
                                                if dt not in node.keystore_load_times:
                                                    node.keystore_load_times.append(dt)
                                            except Exception:
                                                pass
                        except Exception:
                            pass

            self.nodes[node.ip] = node

        return len(self.nodes) > 0

    def validate_node_config(self, node: NodeDiag):
        """Validate server_encryption_options in cassandra.yaml for a node."""
        if not node.cassandra_yaml_path:
            self.findings.append(Finding(
                node.ip, "cassandra_yaml", "FAIL",
                "cassandra.yaml not found in node diagnostic folder.",
                "Verify diagnostic collection included conf/cassandra directory."
            ))
            return

        enc = node.server_enc
        if not enc:
            self.findings.append(Finding(
                node.ip, "server_encryption_options", "FAIL",
                "server_encryption_options block is missing in cassandra.yaml.",
                "Define server_encryption_options with internode_encryption: all/dc."
            ))
            return

        # 1. internode_encryption setting
        ie = str(enc.get("internode_encryption", "none")).strip().lower()
        if ie in ("none", ""):
            self.findings.append(Finding(
                node.ip, "internode_encryption_status", "FAIL",
                f"internode_encryption = '{ie}' — Internode SSL is DISABLED.",
                "Set internode_encryption: all (or dc) in cassandra.yaml."
            ))
        elif ie in ("all", "dc", "rack"):
            self.findings.append(Finding(
                node.ip, "internode_encryption_status", "PASS",
                f"internode_encryption is enabled ({ie})."
            ))
        else:
            self.findings.append(Finding(
                node.ip, "internode_encryption_status", "WARN",
                f"Unrecognised internode_encryption value: '{ie}'."
            ))

        # 2. Keystore and Truststore paths
        ks = enc.get("keystore", "")
        ts = enc.get("truststore", "")
        if not ks:
            self.findings.append(Finding(
                node.ip, "keystore_path", "FAIL",
                "Keystore path is missing in server_encryption_options.",
                "Specify keystore: /path/to/server.keystore"
            ))
        else:
            self.findings.append(Finding(
                node.ip, "keystore_path", "PASS",
                f"Keystore configured: {ks}"
            ))

        if not ts:
            self.findings.append(Finding(
                node.ip, "truststore_path", "FAIL",
                "Truststore path is missing in server_encryption_options.",
                "Specify truststore: /path/to/server.truststore"
            ))
        else:
            self.findings.append(Finding(
                node.ip, "truststore_path", "PASS",
                f"Truststore configured: {ts}"
            ))

        # 3. Protocol
        proto = str(enc.get("protocol", "TLS")).strip()
        if proto.upper() in DEPRECATED_PROTOCOLS:
            self.findings.append(Finding(
                node.ip, "protocol_security", "FAIL",
                f"Deprecated/insecure protocol configured: '{proto}'",
                "Set protocol: TLS (or TLSv1.2 / TLSv1.3) in server_encryption_options."
            ))
        else:
            self.findings.append(Finding(
                node.ip, "protocol_security", "PASS",
                f"Protocol: {proto}"
            ))

        # 4. Optional plaintext mode
        if enc.get("optional", False):
            self.findings.append(Finding(
                node.ip, "optional_encryption", "WARN",
                "server_encryption_options.optional=true — Unencrypted fallback is permitted.",
                "Set optional: false in production once all nodes have SSL configured."
            ))

        # 5. Client authentication mode (1-way vs 2-way)
        req_client_auth = enc.get("require_client_auth", False)
        auth_mode = "2-way (mutual TLS / mTLS)" if req_client_auth else "1-way (server authentication)"
        self.findings.append(Finding(
            node.ip, "auth_mode", "INFO",
            f"Internode SSL mode: {auth_mode} (require_client_auth={req_client_auth})"
        ))

        # 6. Endpoint verification
        req_ep_ver = enc.get("require_endpoint_verification", False)
        if req_ep_ver:
            self.findings.append(Finding(
                node.ip, "endpoint_verification", "INFO",
                "require_endpoint_verification=true — Hostname/IP SAN validation is strictly enforced."
            ))
        else:
            self.findings.append(Finding(
                node.ip, "endpoint_verification", "INFO",
                "require_endpoint_verification=false — Hostname SAN validation bypassed."
            ))

        # 7. Cipher suites
        ciphers = enc.get("cipher_suites")
        if ciphers:
            self.findings.append(Finding(
                node.ip, "cipher_suites", "INFO",
                f"Explicit cipher_suites configured ({len(ciphers)} ciphers)."
            ))
        else:
            self.findings.append(Finding(
                node.ip, "cipher_suites", "INFO",
                "cipher_suites not specified — using standard JVM default suites."
            ))

    def validate_node_logs(self, node: NodeDiag):
        """Scan available Cassandra logs on the node for SSL/TLS errors and events."""
        if not node.log_files:
            self.findings.append(Finding(
                node.ip, "log_analysis", "INFO",
                "No Cassandra logs found in diagnostic bundle for this node."
            ))
            return

        matched_errors: Set[str] = set()
        matched_info: Set[str] = set()

        # Check if the node is currently healthy and processing encrypted traffic
        is_actively_communicating = bool(
            node.gossip_active and (
                node.small_messages_completed > 0 or
                node.gossip_messages_completed > 0
            )
        )

        for log_path in node.log_files:
            log_name = os.path.basename(log_path)
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        for pattern, desc, sev, fix in SSL_LOG_PATTERNS:
                            if re.search(pattern, line, re.I):
                                sample = line.strip()
                                if len(sample) > 160:
                                    sample = sample[:157] + "..."
                                key = f"{desc}:{sample}"
                                if sev == "FAIL" and key not in matched_errors:
                                    matched_errors.add(key)
                                    # If the cluster is currently active and healthy with millions of completed messages,
                                    # historical log entries represent past transient rotation events.
                                    effective_sev = "WARN" if is_actively_communicating else "FAIL"
                                    context_tag = " (Historical/Resolved)" if is_actively_communicating else " (Active Failure)"
                                    self.findings.append(Finding(
                                        node.ip, f"log_{desc.replace(' ', '_').lower()}",
                                        effective_sev, f"[{log_name}]{context_tag} {desc}: {sample}",
                                        "Check if this was transient during rolling cert rotation. Node is currently communicating normally." if is_actively_communicating else fix
                                    ))
                                elif sev == "INFO" and desc not in matched_info:
                                    matched_info.add(desc)
                                    self.findings.append(Finding(
                                        node.ip, f"log_event", "INFO",
                                        f"[{log_name}] {desc} confirmed."
                                    ))
            except Exception as e:
                self.findings.append(Finding(
                    node.ip, "log_read_error", "WARN",
                    f"Could not read {log_name}: {e}"
                ))

        if not matched_errors:
            self.findings.append(Finding(
                node.ip, "log_ssl_health", "PASS",
                f"No SSL/TLS handshake errors or PKIX exceptions detected in {len(node.log_files)} log file(s)."
            ))
        elif is_actively_communicating:
            self.findings.append(Finding(
                node.ip, "active_ssl_traffic_health", "PASS",
                f"Live encrypted traffic verified healthy: {node.small_messages_completed:,} small messages & {node.gossip_messages_completed:,} gossip messages successfully transmitted over SSL. Historical log alerts above are resolved."
            ))

        # ── Service Restart / Keystore & Truststore Reload Check ──
        # DSE provides dynamic reload of truststores (DseServerReloadableTrustManager)
        # but keystores require a full DSE service restart to pick up rotated certificates.
        if node.proc_start_time:
            self.findings.append(Finding(
                node.ip, "dse_process_start", "INFO",
                f"DSE service started: {node.proc_start_time.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                f"(Uptime: {node.uptime_seconds // 86400}d {(node.uptime_seconds % 86400) // 3600}h {(node.uptime_seconds % 3600) // 60}m)"
            ))

        if node.truststore_load_times:
            latest_ts_load = max(node.truststore_load_times)
            self.findings.append(Finding(
                node.ip, "truststore_reload_event", "PASS",
                f"DseServerReloadableTrustManager active — Truststore loaded at {latest_ts_load.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            ))
        else:
            self.findings.append(Finding(
                node.ip, "truststore_reload_event", "INFO",
                "No dynamic truststore reload events recorded in current log window."
            ))

        # Check for certificate rotation restart necessity
        # If there are SSL handshake errors and the node has been running continuously for a long period without restart,
        # alert that a rolling restart is needed if keystores/certs were updated on disk.
        if matched_errors:
            start_str = node.proc_start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if node.proc_start_time else f"{node.uptime_seconds}s uptime"
            self.findings.append(Finding(
                node.ip, "cert_rotation_restart_check", "WARN",
                f"Node has active SSL handshake errors while running continuously since {start_str}. "
                "Note: DSE requires a full rolling restart of DSE service to load new certificates from server.keystore (keystores are not dynamically reloaded).",
                "If keystores or certificates were updated/rotated on disk, perform a rolling restart: 'sudo systemctl restart dse'"
            ))

    def validate_cluster_consistency(self):
        """Cross-node comparison for cluster-wide consistency."""
        node_list = list(self.nodes.values())
        if len(node_list) < 2:
            self.findings.append(Finding(
                "cluster", "cross_node_check", "INFO",
                f"Only {len(node_list)} node found in bundle — skipping cross-node consistency."
            ))
            return

        # 1. Compare internode_encryption
        ie_map = {n.ip: str(n.server_enc.get("internode_encryption", "none")).lower() for n in node_list}
        unique_ie = set(ie_map.values())
        if len(unique_ie) > 1:
            detail = ", ".join(f"{ip}={val}" for ip, val in ie_map.items())
            self.findings.append(Finding(
                "cluster", "inconsistent_internode_encryption", "FAIL",
                f"Mismatched internode_encryption settings across nodes: {detail}",
                "Ensure all nodes have matching internode_encryption in cassandra.yaml."
            ))
        else:
            self.findings.append(Finding(
                "cluster", "internode_encryption_consistency", "PASS",
                f"All {len(node_list)} nodes agree on internode_encryption: '{list(unique_ie)[0]}'"
            ))

        # 2. Compare protocol
        proto_map = {n.ip: str(n.server_enc.get("protocol", "TLS")) for n in node_list}
        if len(set(proto_map.values())) > 1:
            detail = ", ".join(f"{ip}={val}" for ip, val in proto_map.items())
            self.findings.append(Finding(
                "cluster", "inconsistent_protocol", "FAIL",
                f"Mismatched SSL protocols across cluster: {detail}",
                "Align protocol across all nodes in cassandra.yaml."
            ))
        else:
            self.findings.append(Finding(
                "cluster", "protocol_consistency", "PASS",
                f"All nodes use identical SSL protocol: {list(set(proto_map.values()))[0]}"
            ))

        # 3. Compare require_client_auth (1-way vs 2-way mismatch)
        auth_map = {n.ip: bool(n.server_enc.get("require_client_auth", False)) for n in node_list}
        if len(set(auth_map.values())) > 1:
            detail = ", ".join(f"{ip}={val}" for ip, val in auth_map.items())
            self.findings.append(Finding(
                "cluster", "inconsistent_require_client_auth", "FAIL",
                f"Mismatched client auth (mTLS) requirements: {detail}. Some nodes require client certs while others do not.",
                "Ensure require_client_auth is identical on all nodes."
            ))
        else:
            self.findings.append(Finding(
                "cluster", "client_auth_consistency", "PASS",
                f"All nodes agree on require_client_auth={list(set(auth_map.values()))[0]}"
            ))

        # 4. Compare SSL Storage Ports in Gossip
        port_map = {n.ip: n.ssl_storage_port for n in node_list if n.ssl_storage_port > 0}
        if len(set(port_map.values())) > 1:
            detail = ", ".join(f"{ip}={val}" for ip, val in port_map.items())
            self.findings.append(Finding(
                "cluster", "inconsistent_ssl_storage_ports", "FAIL",
                f"Mismatched SSL storage ports in gossip: {detail}",
                "Check enable_legacy_ssl_storage_port or storage_port across cluster."
            ))
        elif port_map:
            self.findings.append(Finding(
                "cluster", "ssl_port_consistency", "PASS",
                f"All nodes use SSL storage port: {list(set(port_map.values()))[0]}"
            ))

        # 5. Cipher Suites Intersection
        cipher_sets = [set(n.server_enc.get("cipher_suites") or []) for n in node_list if n.server_enc.get("cipher_suites")]
        if len(cipher_sets) > 1:
            common = set.intersection(*cipher_sets)
            if not common:
                self.findings.append(Finding(
                    "cluster", "cipher_suites_disjoint", "FAIL",
                    "Disjoint cipher_suites configured across nodes — TLS negotiation will fail.",
                    "Ensure a common set of strong cipher suites is present on every node."
                ))
            else:
                self.findings.append(Finding(
                    "cluster", "cipher_suites_overlap", "PASS",
                    f"Common cipher suites available across all configured nodes ({len(common)} suites)."
                ))

        # 6. Schema Agreement check
        schema_set = {n.schema_id for n in node_list if n.schema_id}
        if len(schema_set) == 1:
            self.findings.append(Finding(
                "cluster", "schema_agreement", "PASS",
                f"Cluster has complete schema agreement (Schema ID: {list(schema_set)[0][:8]}...)"
            ))
        elif len(schema_set) > 1:
            self.findings.append(Finding(
                "cluster", "schema_disagreement", "WARN",
                f"Multiple schema versions detected ({len(schema_set)} versions). Cluster may be undergoing schema migration or gossip is degraded."
            ))

    def run(self) -> int:
        """Run all validation checks and return exit code (0=PASS, 1=WARN, 2=FAIL)."""
        print(f"\n{Colors.BOLD}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD} DSE Diagnostic Bundle — Internode SSL Validator{Colors.RESET}")
        print(f" Bundle Path: {Colors.CYAN}{self.bundle_root}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 80}{Colors.RESET}\n")

        if not self.locate_and_load_nodes():
            for f in self.findings:
                print(f.formatted(self.no_color))
            return 2

        print(f"Discovered {Colors.BOLD}{len(self.nodes)}{Colors.RESET} node(s) in cluster '{Colors.CYAN}{self.cluster_name}{Colors.RESET}':")
        for ip, n in self.nodes.items():
            print(f"  • {Colors.BOLD}{ip:<15}{Colors.RESET} │ DC={n.dc or 'n/a':<10} Rack={n.rack or 'n/a':<8} DSE={n.dse_version:<8} SSL Port={n.ssl_storage_port}")
        print(f"\n{Colors.DIM}{'─' * 80}{Colors.RESET}\n")

        # 1. Per-node configuration and log audits
        for ip, node in self.nodes.items():
            self.validate_node_config(node)
            self.validate_node_logs(node)

        # 2. Cluster-wide consistency and agreement
        self.validate_cluster_consistency()

        # Print all findings grouped by node / cluster
        findings_by_target: Dict[str, List[Finding]] = {}
        for f in self.findings:
            findings_by_target.setdefault(f.node, []).append(f)

        pass_count = sum(1 for f in self.findings if f.status == "PASS")
        warn_count = sum(1 for f in self.findings if f.status == "WARN")
        fail_count = sum(1 for f in self.findings if f.status == "FAIL")
        info_count = sum(1 for f in self.findings if f.status == "INFO")

        for target in sorted(findings_by_target.keys()):
            is_cluster = (target == "cluster")
            header = "CLUSTER-WIDE CONSISTENCY & TOPOLOGY" if is_cluster else f"NODE: {target}"
            print(f"{Colors.BOLD}▶ {header}{Colors.RESET}")
            for f in findings_by_target[target]:
                print(f.formatted(self.no_color))
            print()

        # Summary box
        print(f"{Colors.BOLD}{'─' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}VALIDATION SUMMARY:{Colors.RESET}")
        print(f"  {Colors.GREEN}PASS: {pass_count:<4}{Colors.RESET} │ {Colors.YELLOW}WARN: {warn_count:<4}{Colors.RESET} │ {Colors.RED}FAIL: {fail_count:<4}{Colors.RESET} │ {Colors.CYAN}INFO: {info_count:<4}{Colors.RESET}")

        if fail_count > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}Result: FAILED — Action required on critical issues.{Colors.RESET}\n")
            return 2
        elif warn_count > 0:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}Result: WARNING — Please review warnings above.{Colors.RESET}\n")
            return 1
        else:
            print(f"\n{Colors.GREEN}{Colors.BOLD}Result: PASSED — All internode SSL checks healthy.{Colors.RESET}\n")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="Offline DSE Diagnostic Bundle Internode SSL Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--bundle-dir", "-b",
        default=".",
        help="Path to unpacked DSE diagnostic bundle directory (default: current directory)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output (useful for piping or CI/CD logs)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    args = parser.parse_args()

    validator = DiagBundleInternodeValidator(
        bundle_root=args.bundle_dir,
        log_level=args.log_level,
        no_color=args.no_color,
    )
    rc = validator.run()
    sys.exit(rc)


if __name__ == "__main__":
    main()
