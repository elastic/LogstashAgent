#!/usr/bin/env python3
#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Standalone LogstashUI scale test using wire-compatible virtual agents."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import ssl
import sys
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

SCALE_PREFIX = "scale-test-"
DEFAULT_TIMEOUT_SECONDS = 30.0
ENROLLMENT_CONCURRENCY = 100
PROGRESS_EVERY = 100
CHECKIN_INTERVAL_SECONDS = 5.0
CHECKIN_JITTER_SECONDS = 1.0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percent
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def format_latency(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value < 1:
        return f"{value * 1000:.0f}ms"
    return f"{value:.2f}s"


def classify_error(text: str, status_code: int | None = None) -> str:
    lowered = text.lower()
    if "database is locked" in lowered or "database table is locked" in lowered:
        return "sqlite_locked"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if status_code is not None:
        return f"http_{status_code}"
    return text.split(":", 1)[0][:80] or "unknown"


@dataclass
class RequestResult:
    ok: bool
    latency: float
    status_code: int | None
    error: str | None
    sent_bytes: int
    received_bytes: int
    completed_at: float


@dataclass
class MetricBucket:
    name: str
    results: list[RequestResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)

    def record(self, result: RequestResult) -> None:
        if not self.results:
            self.started_at = result.completed_at - result.latency
        self.results.append(result)

    @property
    def attempts(self) -> int:
        return len(self.results)

    @property
    def successes(self) -> int:
        return sum(result.ok for result in self.results)

    @property
    def failures(self) -> int:
        return self.attempts - self.successes

    def summary(self) -> dict[str, Any]:
        latencies = [result.latency for result in self.results]
        statuses = Counter(
            str(result.status_code)
            for result in self.results
            if result.status_code is not None
        )
        errors = Counter(
            classify_error(result.error or "unknown", result.status_code)
            for result in self.results
            if not result.ok
        )
        error_messages = Counter(
            (result.error or "unknown")[:300]
            for result in self.results
            if not result.ok
        )
        if self.results:
            elapsed = max(result.completed_at for result in self.results) - self.started_at
        else:
            elapsed = 0.0
        return {
            "name": self.name,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate_percent": round(self.successes / self.attempts * 100, 3)
            if self.attempts
            else 0.0,
            "elapsed_seconds": round(max(0.0, elapsed), 3),
            "requests_per_second": round(self.attempts / elapsed, 3) if elapsed > 0 else 0.0,
            "latency_seconds": {
                "average": sum(latencies) / len(latencies) if latencies else None,
                "median": percentile(latencies, 0.50),
                "min": min(latencies) if latencies else None,
                "p50": percentile(latencies, 0.50),
                "p95": percentile(latencies, 0.95),
                "p99": percentile(latencies, 0.99),
                "max": max(latencies) if latencies else None,
            },
            "status_codes": dict(sorted(statuses.items())),
            "errors": dict(errors.most_common()),
            "error_messages": dict(error_messages.most_common(20)),
            "bytes_sent": sum(result.sent_bytes for result in self.results),
            "bytes_received": sum(result.received_bytes for result in self.results),
        }

    def progress_line(self, label: str, total: int | None = None) -> str:
        summary = self.summary()
        latencies = summary["latency_seconds"]
        count = f"{self.attempts:,}"
        if total is not None:
            count += f"/{total:,}"
        locked = summary["errors"].get("sqlite_locked", 0)
        timeouts = summary["errors"].get("timeout", 0)
        return (
            f"{label} {count} | success {self.successes:,} | failed {self.failures:,} "
            f"| {summary['requests_per_second']:.1f}/sec "
            f"| avg {format_latency(latencies['average'])} "
            f"| median {format_latency(latencies['median'])} "
            f"| min {format_latency(latencies['min'])} "
            f"| max {format_latency(latencies['max'])} "
            f"| p95 {format_latency(latencies['p95'])} "
            f"| p99 {format_latency(latencies['p99'])} "
            f"| locked {locked:,} | timeouts {timeouts:,}"
        )


@dataclass
class Identity:
    index: int
    agent_id: str
    host: str
    host_short: str
    callback_ip: str
    csr_pem: str


@dataclass
class VirtualAgent:
    identity: Identity
    connection_id: int
    api_key: str
    policy_id: int
    policy: dict[str, Any]
    rng: random.Random
    revision: int = 0
    checkin_count: int = 0
    keystore: dict[str, str] = field(default_factory=dict)
    pipelines: dict[str, dict[str, Any]] = field(default_factory=dict)
    snmp_pipelines: dict[str, str] = field(default_factory=dict)
    snmp_keystore: dict[str, str] = field(default_factory=dict)
    keystore_password_hash: str = ""

    @classmethod
    def from_enrollment(
        cls, identity: Identity, response: dict[str, Any], seed: int
    ) -> "VirtualAgent":
        return cls(
            identity=identity,
            connection_id=int(response["connection_id"]),
            api_key=str(response["api_key"]),
            policy_id=int(response["policy_id"]),
            policy=response.get("policy_config") or {},
            rng=random.Random(seed + identity.index * 1_000_003),
        )

    def managed_rollup(self) -> str:
        parts: list[str] = []
        for name in sorted(self.snmp_pipelines):
            parts.append(f"p:{name}={self.snmp_pipelines[name]}")
        for name in sorted(self.snmp_keystore):
            parts.append(f"k:{name}={self.snmp_keystore[name]}")
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()

    def status_blob(self) -> dict[str, Any]:
        now = utc_now()
        self.checkin_count += 1
        roll = self.rng.random()
        warnings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        fatals: list[dict[str, Any]] = []
        logstash_state = "running"
        last_shutdown_ts = None
        last_startup_ts = int((now.timestamp() - 86_400) * 1000)

        def log_entry(level: str, number: int) -> dict[str, Any]:
            return {
                "ts": int(now.timestamp() * 1000) - number * 137,
                "logger": "org.logstash.execution.AbstractPipelineExt",
                "message": f"Synthetic {level.lower()} from scale agent {self.identity.index}",
            }

        if roll < 0.80:
            pass
        elif roll < 0.95:
            warnings = [log_entry("WARN", i) for i in range(1, self.rng.randint(2, 4))]
        elif roll < 0.99:
            warnings = [log_entry("WARN", 1)]
            errors = [log_entry("ERROR", 2)]
        else:
            fatals = [log_entry("FATAL", 1)]
            logstash_state = "restarting"
            last_shutdown_ts = int(now.timestamp() * 1000) - 500

        uptime_seconds = (
            86_400
            + self.identity.index * 3
            + int(self.checkin_count * CHECKIN_INTERVAL_SECONDS)
        )
        binary_path = self.policy.get("binary_path") or ""
        return {
            "settings_path_found": True,
            "logs_path_found": True,
            "binary_path_found": True,
            "config_files": {
                "logstash_yml": True,
                "jvm_options": True,
                "log4j2_properties": True,
                "logstash_keystore": True,
            },
            "binaries": {"logstash": True, "logstash_keystore": True},
            "log_file": {
                "exists": True,
                "last_modified": now.isoformat(),
                "size_bytes": 8_388_608 + self.identity.index * 101,
            },
            "problems": None,
            "agent_version": "0.5.1",
            "mode": "managed",
            "logstash_source": self.policy.get("logstash_source") or "SYSTEM",
            "logstash_version": self.policy.get("logstash_version") or "",
            "logstash_version_resolved": self.policy.get("logstash_version") or "9.0.0",
            "logstash_binary": f"{binary_path.rstrip('/')}/logstash",
            "logstash_download_dir": self.policy.get("logstash_download_dir") or "",
            "last_runtime_apply": None,
            "logstash_api": {
                "accessible": True,
                "status": "green",
                "version": {"number": self.policy.get("logstash_version") or "9.0.0"},
                "host": self.identity.host_short,
                "error": None,
            },
            "health_report": {
                "accessible": True,
                "status": "green",
                "symptom": "No health issues",
                "indicators": {
                    "pipelines": {
                        "status": "green",
                        "symptom": "All pipelines are running",
                        "diagnosis": [],
                        "indicators": {},
                    }
                },
                "error": None,
            },
            "node_stats": {
                "accessible": True,
                "jvm": {
                    "heap_used_percent": 31 + self.identity.index % 17,
                    "uptime_in_millis": uptime_seconds * 1000,
                    "gc_old_collection_count": self.identity.index % 11,
                    "gc_young_collection_count": 100 + self.checkin_count,
                },
                "process": {
                    "cpu_percent": 3 + self.identity.index % 13,
                    "open_file_descriptors": 160 + self.identity.index % 30,
                },
                "events": {
                    "in": 1_000_000 + self.checkin_count * 5_000,
                    "filtered": 999_800 + self.checkin_count * 5_000,
                    "out": 999_750 + self.checkin_count * 5_000,
                },
                "pipeline": {"workers": 2, "batch_size": 125},
                "reloads": {"successes": 1, "failures": 0},
                "error": None,
            },
            "process_info": {
                "available": True,
                "running": True,
                "pid": 10_000 + self.identity.index,
                "status": "sleeping",
                "cpu_percent": 4.2,
                "memory_rss_mb": 1024.0 + self.identity.index % 256,
                "memory_percent": 6.5,
                "num_threads": 74,
                "uptime": f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m",
                "uptime_seconds": uptime_seconds,
            },
            "last_policy_apply": None,
            "last_apply": {},
            "logwatcher": {
                "logstash_state": logstash_state,
                "is_restarting": logstash_state == "restarting",
                "warnings_since_last_checkin": warnings,
                "errors_since_last_checkin": errors,
                "fatals_since_last_checkin": fatals,
                "last_shutdown_ts": last_shutdown_ts,
                "last_startup_ts": last_startup_ts,
                "last_shutdown_dt": now.isoformat() if last_shutdown_ts else None,
                "last_startup_dt": datetime.fromtimestamp(
                    last_startup_ts / 1000, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC"),
            },
            "callback_host": self.identity.host,
            "callback_ip": self.identity.callback_ip,
        }

    def checkin_payload(self) -> dict[str, Any]:
        return {
            "connection_id": self.connection_id,
            "revision_number": self.revision,
            "status_blob": self.status_blob(),
            "managed_state_hashes": {"snmp": self.managed_rollup()},
            "host": self.identity.host,
            "callback_ip": self.identity.callback_ip,
        }

    def config_payload(self, server_paths: dict[str, Any]) -> dict[str, Any]:
        policy = self.policy

        def policy_hash(name: str) -> str:
            content = policy.get(name) or ""
            return hashlib.sha256(str(content).encode("utf-8")).hexdigest()

        return {
            "connection_id": self.connection_id,
            "logstash_yml_hash": policy_hash("logstash_yml"),
            "jvm_options_hash": policy_hash("jvm_options"),
            "log4j2_properties_hash": policy_hash("log4j2_properties"),
            "settings_path": server_paths.get("settings_path") or policy.get("settings_path") or "",
            "logs_path": server_paths.get("logs_path") or policy.get("logs_path") or "",
            "binary_path": server_paths.get("binary_path") or policy.get("binary_path") or "",
            "logstash_source": policy.get("logstash_source") or "SYSTEM",
            "logstash_version": policy.get("logstash_version") or "",
            "logstash_download_dir": policy.get("logstash_download_dir") or "",
            "keystore": self.keystore,
            "keystore_password_hash": self.keystore_password_hash,
            "pipelines": self.pipelines,
            "snmp_pipelines": self.snmp_pipelines,
            "snmp_keystore": self.snmp_keystore,
        }

    def apply_config_response(self, response: dict[str, Any]) -> None:
        changes = response.get("changes") or {}
        for key in ("settings_path", "logs_path", "binary_path"):
            if changes.get(key):
                self.policy[key] = changes[key]
        runtime = changes.get("logstash_runtime")
        if runtime:
            self.policy["logstash_source"] = runtime.get("source") or "SYSTEM"
            self.policy["logstash_version"] = runtime.get("version") or ""
            self.policy["logstash_download_dir"] = runtime.get("download_dir") or ""
        pipeline_changes = changes.get("pipelines") or {}
        for name in pipeline_changes.get("delete", []):
            self.pipelines.pop(name, None)
        for name, details in pipeline_changes.get("set", {}).items():
            self.pipelines[name] = {"config_hash": details.get("pipeline_hash") or ""}

        snmp_changes = response.get("snmp_changes") or {}
        snmp_pipeline_changes = snmp_changes.get("pipelines") or {}
        for name in snmp_pipeline_changes.get("delete", []):
            self.snmp_pipelines.pop(name, None)
        for name, details in snmp_pipeline_changes.get("set", {}).items():
            self.snmp_pipelines[name] = details.get("pipeline_hash") or ""
        snmp_keystore_changes = snmp_changes.get("keystore") or {}
        for name in snmp_keystore_changes.get("delete", []):
            self.snmp_keystore.pop(name, None)
        for name, encrypted in snmp_keystore_changes.get("set", {}).items():
            try:
                from cryptography.fernet import Fernet

                key = base64.urlsafe_b64encode(
                    hashlib.sha256(self.api_key.encode("utf-8")).digest()
                )
                plaintext = Fernet(key).decrypt(encrypted.encode("utf-8"))
                self.snmp_keystore[name] = hashlib.sha256(plaintext).hexdigest()
            except Exception:
                # A subsequent check-in will correctly flag the still-dirty source.
                pass
        self.revision = int(response.get("current_revision", self.revision))


@dataclass
class ScaleState:
    args: argparse.Namespace
    run_id: str
    client: httpx.AsyncClient
    enrollment: MetricBucket = field(default_factory=lambda: MetricBucket("enrollment"))
    initial_checkins: MetricBucket = field(
        default_factory=lambda: MetricBucket("initial_checkins")
    )
    periodic_checkins: MetricBucket = field(
        default_factory=lambda: MetricBucket("periodic_checkins")
    )
    config_fetches: MetricBucket = field(
        default_factory=lambda: MetricBucket("config_fetches")
    )
    cleanup: MetricBucket = field(default_factory=lambda: MetricBucket("cleanup"))
    agents: list[VirtualAgent] = field(default_factory=list)
    agent_tasks: list[asyncio.Task[None]] = field(default_factory=list)
    checkins_done: asyncio.Event = field(default_factory=asyncio.Event)
    started_at_utc: datetime = field(default_factory=utc_now)
    interrupted: bool = False


def decode_enrollment_token(encoded_token: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(encoded_token.encode("utf-8")).decode("utf-8")
        payload = json.loads(decoded)
    except Exception as exc:
        raise ValueError(f"Invalid enrollment token: {exc}") from exc
    if not payload.get("enrollment_token"):
        raise ValueError("Invalid enrollment token: missing enrollment_token")
    return payload


def build_csr(host: str, callback_ip: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sans = [
        x509.DNSName("localhost"),
        x509.DNSName("logstashagent"),
        x509.DNSName(host),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
        x509.IPAddress(ipaddress.ip_address(callback_ip)),
    ]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LogstashAgent"),
                    x509.NameAttribute(NameOID.COMMON_NAME, host),
                ]
            )
        )
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def build_identity(index: int, run_id: str) -> Identity:
    host_short = f"{SCALE_PREFIX}{run_id}-{index:06d}"
    host = f"{host_short}.invalid"
    number = index % 0xFFFFFF
    callback_ip = f"10.{(number >> 16) & 0xFF}.{(number >> 8) & 0xFF}.{number & 0xFF}"
    return Identity(
        index=index,
        agent_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"logstash-agent:{run_id}:{index}")),
        host=host,
        host_short=host_short,
        callback_ip=callback_ip,
        csr_pem=build_csr(host, callback_ip),
    )


async def generate_identities(count: int, run_id: str, *, offset: int = 0) -> list[Identity]:
    label = f"(retry offset +{offset:,}) " if offset else ""
    print(f"Preparing {count:,} unique RSA keys and CSRs {label}(excluded from server timings)...")
    worker_count = min(32, max(4, (os.cpu_count() or 4) * 2))
    semaphore = asyncio.Semaphore(worker_count)
    completed = 0

    async def one(index: int) -> Identity:
        nonlocal completed
        async with semaphore:
            identity = await asyncio.to_thread(build_identity, index, run_id)
        completed += 1
        if completed % 1_000 == 0 or completed == count:
            print(f"Prepared identities {completed:,}/{count:,}")
        return identity

    return list(
        await asyncio.gather(*(one(index) for index in range(offset + 1, offset + count + 1)))
    )


async def post_json(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
) -> tuple[RequestResult, dict[str, Any] | None]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    started = time.monotonic()
    status_code = None
    received = 0
    error = None
    data = None
    try:
        response = await client.post(url, content=body, headers=request_headers)
        status_code = response.status_code
        received = len(response.content)
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            error = f"non_json_response: {response.text[:300]}"
        if error is None and not response.is_success:
            error = str((data or {}).get("error") or response.text[:300] or response.reason_phrase)
        if error is None and isinstance(data, dict) and data.get("success") is False:
            error = str(data.get("error") or data.get("message") or "success=false")
    except httpx.TimeoutException as exc:
        error = f"timeout: {exc}"
    except httpx.HTTPError as exc:
        error = f"{type(exc).__name__}: {exc}"
    latency = time.monotonic() - started
    return (
        RequestResult(
            ok=error is None,
            latency=latency,
            status_code=status_code,
            error=error,
            sent_bytes=len(body),
            received_bytes=received,
            completed_at=time.monotonic(),
        ),
        data,
    )


async def enroll_identity(state: ScaleState, identity: Identity) -> VirtualAgent | None:
    payload = {
        "enrollment_token": state.args.enrollment_token,
        "host": identity.host,
        "host_short": identity.host_short,
        "agent_id": identity.agent_id,
        "callback_ip": identity.callback_ip,
        "csr_pem": identity.csr_pem,
    }
    result, response = await post_json(
        state.client,
        f"{state.args.logstash_ui_url}/ConnectionManager/Enroll/",
        payload,
    )
    if result.ok:
        required = {"connection_id", "api_key", "policy_id", "policy_config"}
        missing = required - set(response or {})
        if missing:
            result.ok = False
            result.error = f"enrollment response missing: {', '.join(sorted(missing))}"
    state.enrollment.record(result)
    if state.enrollment.attempts % PROGRESS_EVERY == 0:
        print(state.enrollment.progress_line("Enrollment", state.args.num_of_agents))
    if not result.ok or response is None:
        return None
    return VirtualAgent.from_enrollment(identity, response, state.args.seed)


async def fetch_config(
    state: ScaleState, agent: VirtualAgent, checkin_response: dict[str, Any]
) -> None:
    result, response = await post_json(
        state.client,
        f"{state.args.logstash_ui_url}/ConnectionManager/GetConfigChanges/",
        agent.config_payload(checkin_response),
        headers={"Authorization": f"ApiKey {agent.api_key}"},
    )
    state.config_fetches.record(result)
    if result.ok and response is not None:
        agent.apply_config_response(response)


async def check_in(state: ScaleState, agent: VirtualAgent, *, initial: bool) -> None:
    bucket = state.initial_checkins if initial else state.periodic_checkins
    result, response = await post_json(
        state.client,
        f"{state.args.logstash_ui_url}/ConnectionManager/CheckIn/",
        agent.checkin_payload(),
        headers={"Authorization": f"ApiKey {agent.api_key}"},
    )
    bucket.record(result)
    total_checkins = state.initial_checkins.attempts + state.periodic_checkins.attempts
    if total_checkins % PROGRESS_EVERY == 0:
        combined = MetricBucket("all_checkins")
        combined.started_at = min(
            state.initial_checkins.started_at, state.periodic_checkins.started_at
        )
        combined.results = state.initial_checkins.results + state.periodic_checkins.results
        print(combined.progress_line("Check-ins"))
    if not result.ok or response is None:
        return
    server_revision = int(response.get("current_revision_number", 0))
    managed = response.get("managed_changes_available") or {}
    policy_dirty = server_revision != agent.revision
    snmp_dirty = bool(managed.get("snmp"))
    server_source = (response.get("logstash_source") or "SYSTEM").upper()
    server_version = response.get("logstash_version") or ""
    runtime_dirty = (
        server_source != (agent.policy.get("logstash_source") or "SYSTEM").upper()
        or server_version != (agent.policy.get("logstash_version") or "")
    )
    if policy_dirty or snmp_dirty or runtime_dirty:
        await fetch_config(state, agent, response)


async def agent_loop(state: ScaleState, agent: VirtualAgent) -> None:
    await check_in(state, agent, initial=True)
    for _ in range(1, state.args.num_check_ins):
        await asyncio.sleep(
            CHECKIN_INTERVAL_SECONDS
            + agent.rng.uniform(-CHECKIN_JITTER_SECONDS, CHECKIN_JITTER_SECONDS)
        )
        await check_in(state, agent, initial=False)


def duplicate_allocations(agents: list[VirtualAgent]) -> dict[str, dict[str, list[int]]]:
    fields = ("instance_id", "agent_api_port", "logstash_api_port")
    duplicates: dict[str, dict[str, list[int]]] = {}
    for field_name in fields:
        seen: dict[str, list[int]] = defaultdict(list)
        for agent in agents:
            value = agent.policy.get(field_name)
            if value is not None:
                seen[str(value)].append(agent.connection_id)
        duplicates[field_name] = {
            value: ids for value, ids in seen.items() if len(ids) > 1
        }
    return duplicates


async def minute_reporter(state: ScaleState) -> None:
    minute = 0
    previous_periodic = 0
    while not state.checkins_done.is_set():
        try:
            await asyncio.wait_for(state.checkins_done.wait(), timeout=60.0)
            return
        except TimeoutError:
            pass
        minute += 1
        current = state.periodic_checkins.attempts
        interval_attempts = current - previous_periodic
        previous_periodic = current
        summary = state.periodic_checkins.summary()
        latencies = summary["latency_seconds"]
        print(
            f"Minute {minute} | active agents {len(state.agents):,} "
            f"| periodic attempts {current:,} (+{interval_attempts:,}) "
            f"| success {state.periodic_checkins.successes:,} "
            f"| failed {state.periodic_checkins.failures:,} "
            f"| config fetches {state.config_fetches.attempts:,} "
            f"| locked {summary['errors'].get('sqlite_locked', 0):,} "
            f"| timeouts {summary['errors'].get('timeout', 0):,} "
            f"| avg {format_latency(latencies['average'])} "
            f"| median {format_latency(latencies['median'])} "
            f"| min {format_latency(latencies['min'])} "
            f"| max {format_latency(latencies['max'])} "
            f"| p95 {format_latency(latencies['p95'])} "
            f"| p99 {format_latency(latencies['p99'])}"
        )


async def initial_checkin_reporter(state: ScaleState) -> None:
    while state.initial_checkins.attempts < len(state.agents):
        await asyncio.sleep(0.05)
    print(state.initial_checkins.progress_line("Initial check-ins final", len(state.agents)))


async def authenticate_admin(args: argparse.Namespace) -> httpx.AsyncClient:
    client = httpx.AsyncClient(
        verify=args.ssl_context,
        timeout=httpx.Timeout(DEFAULT_TIMEOUT_SECONDS),
        follow_redirects=True,
    )
    login_url = f"{args.logstash_ui_url}/Management/Login/"
    try:
        page = await client.get(login_url)
        page.raise_for_status()
        match = re.search(
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)',
            page.text,
        )
        csrf_token = match.group(1) if match else client.cookies.get("csrftoken")
        if not csrf_token:
            raise RuntimeError("LogstashUI login page did not provide a CSRF token")
        response = await client.post(
            login_url,
            data={
                "username": args.username,
                "password": args.password,
                "csrfmiddlewaretoken": csrf_token,
            },
            headers={"Referer": login_url},
        )
        if response.url.path.endswith("/Management/Login/") or "id_password" in response.text:
            raise RuntimeError("LogstashUI administrator login failed")
        return client
    except Exception:
        await client.aclose()
        raise


async def discover_scale_connections(
    client: httpx.AsyncClient, args: argparse.Namespace
) -> list[dict[str, Any]]:
    response = await client.get(f"{args.logstash_ui_url}/ConnectionManager/GetConnections/")
    response.raise_for_status()
    try:
        connections = response.json()
    except ValueError as exc:
        raise RuntimeError("GetConnections returned a non-JSON response") from exc
    return [
        connection
        for connection in connections
        if connection.get("connection_type") == "AGENT"
        and str(connection.get("name") or "").startswith(SCALE_PREFIX)
    ]


def confirm_cleanup(count: int, assume_yes: bool) -> bool:
    if count == 0:
        return True
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Cleanup requires confirmation; rerun with --yes in a non-interactive shell.")
        return False
    answer = input(f"Found {count:,} scale-test agents. Delete them? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


async def cleanup_scale_connections(
    args: argparse.Namespace, bucket: MetricBucket | None = None
) -> tuple[int, int, bool]:
    bucket = bucket or MetricBucket("cleanup")
    client = await authenticate_admin(args)
    try:
        connections = await discover_scale_connections(client, args)
        if not connections:
            print("Cleanup: no scale-test agents found.")
            return 0, 0, True
        if not confirm_cleanup(len(connections), args.yes):
            print("Cleanup cancelled; scale-test agents were left in LogstashUI.")
            return 0, len(connections), False

        csrf_token = client.cookies.get("csrftoken")
        if not csrf_token:
            raise RuntimeError("Authenticated session has no CSRF token")
        deleted = 0
        for connection in connections:
            connection_id = int(connection["id"])
            started = time.monotonic()
            status_code = None
            error = None
            received = 0
            try:
                response = await client.post(
                    f"{args.logstash_ui_url}/ConnectionManager/DeleteConnection/{connection_id}/",
                    headers={
                        "X-CSRFToken": csrf_token,
                        "Referer": f"{args.logstash_ui_url}/ConnectionManager/",
                    },
                )
                status_code = response.status_code
                received = len(response.content)
                if response.status_code == 404:
                    deleted += 1
                elif response.is_success:
                    deleted += 1
                else:
                    error = response.text[:300] or response.reason_phrase
            except httpx.TimeoutException as exc:
                error = f"timeout: {exc}"
            except httpx.HTTPError as exc:
                error = f"{type(exc).__name__}: {exc}"
            bucket.record(
                RequestResult(
                    ok=error is None,
                    latency=time.monotonic() - started,
                    status_code=status_code,
                    error=error,
                    sent_bytes=0,
                    received_bytes=received,
                    completed_at=time.monotonic(),
                )
            )
            if bucket.attempts % PROGRESS_EVERY == 0:
                print(bucket.progress_line("Cleanup", len(connections)))
        failed = len(connections) - deleted
        print(f"Cleanup complete | deleted {deleted:,} | failed {failed:,}")
        return deleted, failed, failed == 0
    finally:
        await client.aclose()


def build_report(state: ScaleState) -> dict[str, Any]:
    finished = utc_now()
    all_checkins = MetricBucket("all_checkins")
    all_checkins.started_at = min(
        state.initial_checkins.started_at, state.periodic_checkins.started_at
    )
    all_checkins.results = (
        state.initial_checkins.results + state.periodic_checkins.results
    )
    return {
        "run_id": state.run_id,
        "started_at": state.started_at_utc.isoformat(),
        "finished_at": finished.isoformat(),
        "elapsed_seconds": round((finished - state.started_at_utc).total_seconds(), 3),
        "interrupted": state.interrupted,
        "configuration": {
            "logstash_ui_url": state.args.logstash_ui_url,
            "requested_agents": state.args.num_of_agents,
            "num_check_ins_per_agent": state.args.num_check_ins,
            "enrollment_concurrency": ENROLLMENT_CONCURRENCY,
            "checkin_interval_seconds": CHECKIN_INTERVAL_SECONDS,
            "checkin_jitter_seconds": CHECKIN_JITTER_SECONDS,
            "seed": state.args.seed,
            "connection_reuse": False,
            "agent_name_prefix": SCALE_PREFIX,
        },
        "enrolled_agents": len(state.agents),
        "managed_allocation_duplicates": duplicate_allocations(state.agents),
        "metrics": {
            "enrollment": state.enrollment.summary(),
            "initial_checkins": state.initial_checkins.summary(),
            "periodic_checkins": state.periodic_checkins.summary(),
            "all_checkins": all_checkins.summary(),
            "config_fetches": state.config_fetches.summary(),
            "cleanup": state.cleanup.summary(),
        },
    }


def print_final_report(report: dict[str, Any], report_path: Path) -> None:
    metrics = report["metrics"]
    duplicates = report["managed_allocation_duplicates"]
    print("\n" + "=" * 78)
    print("LOGSTASHUI SCALE TEST FINAL REPORT")
    print("=" * 78)
    print(f"Run ID:              {report['run_id']}")
    print(f"Requested agents:    {report['configuration']['requested_agents']:,}")
    print(f"Enrolled agents:     {report['enrolled_agents']:,}")
    print(f"Check-ins per agent: {report['configuration']['num_check_ins_per_agent']:,}")
    print(f"Total elapsed:       {report['elapsed_seconds']:.1f}s")
    print(f"Interrupted:         {'yes' if report['interrupted'] else 'no'}")
    for key in (
        "enrollment",
        "initial_checkins",
        "periodic_checkins",
        "config_fetches",
        "cleanup",
    ):
        item = metrics[key]
        latency = item["latency_seconds"]
        print(
            f"{key.replace('_', ' ').title():20} "
            f"attempts={item['attempts']:,} success={item['successes']:,} "
            f"failed={item['failures']:,} rate={item['requests_per_second']:.1f}/sec "
            f"avg={format_latency(latency['average'])} "
            f"median={format_latency(latency['median'])} "
            f"min={format_latency(latency['min'])} "
            f"max={format_latency(latency['max'])} "
            f"p95={format_latency(latency['p95'])} "
            f"p99={format_latency(latency['p99'])}"
        )
        if item["errors"]:
            print(f"  errors: {item['errors']}")
    for field_name, values in duplicates.items():
        duplicate_connections = sum(len(ids) for ids in values.values())
        print(
            f"Duplicate {field_name:17} values={len(values):,} "
            f"affected_connections={duplicate_connections:,}"
        )
    total_sent = sum(
        metrics[name]["bytes_sent"]
        for name in ("enrollment", "all_checkins", "config_fetches", "cleanup")
    )
    total_received = sum(
        metrics[name]["bytes_received"]
        for name in ("enrollment", "all_checkins", "config_fetches", "cleanup")
    )
    print(f"Bytes sent/received: {total_sent:,} / {total_received:,}")
    print(f"JSON report:         {report_path}")
    print("=" * 78)


def save_report(state: ScaleState) -> tuple[dict[str, Any], Path]:
    report = build_report(state)
    output_dir = Path(state.args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"scale-test-{state.run_id}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report, path


# ---------------------------------------------------------------------------
# TSV reporting
# ---------------------------------------------------------------------------

def _tv(v: Any, precision: int = 6) -> str:
    """Format a scalar for TSV: None → 'n/a', floats rounded, rest stringified."""
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.{precision}f}"
    return str(v).replace("\t", " ")


def _errors_cell(errors: dict[str, int], limit: int = 5) -> str:
    """Render top errors as 'key=count; key=count' — safe for a single TSV cell."""
    if not errors:
        return "none"
    return "; ".join(f"{k}={v}" for k, v in list(errors.items())[:limit])


ENROLLMENT_TSV_HEADERS: list[str] = [
    "run_id", "started_at", "requested_agents", "enrolled_agents",
    "attempts", "successes", "failures", "success_rate_pct",
    "elapsed_s", "req_per_s",
    "lat_avg_s", "lat_median_s", "lat_min_s", "lat_max_s", "lat_p95_s", "lat_p99_s",
    "bytes_sent", "bytes_received", "top_errors",
]

CHECKIN_TSV_HEADERS: list[str] = [
    "run_id", "started_at", "requested_agents", "enrolled_agents", "num_check_ins_per_agent",
    "initial_attempts", "initial_successes", "initial_failures",
    "periodic_attempts", "periodic_successes", "periodic_failures",
    "all_attempts", "all_successes", "all_failures",
    "all_success_rate_pct", "all_elapsed_s", "all_req_per_s",
    "lat_avg_s", "lat_median_s", "lat_min_s", "lat_max_s", "lat_p95_s", "lat_p99_s",
    "config_fetch_attempts", "config_fetch_successes", "config_fetch_failures",
    "bytes_sent", "bytes_received", "top_errors",
]


def _enrollment_tsv_row(report: dict[str, Any]) -> list[str]:
    m = report["metrics"]["enrollment"]
    lat = m["latency_seconds"]
    return [
        report["run_id"],
        report["started_at"],
        _tv(report["configuration"]["requested_agents"]),
        _tv(report["enrolled_agents"]),
        _tv(m["attempts"]),
        _tv(m["successes"]),
        _tv(m["failures"]),
        _tv(m["success_rate_percent"]),
        _tv(m["elapsed_seconds"]),
        _tv(m["requests_per_second"]),
        _tv(lat["average"]),
        _tv(lat["median"]),
        _tv(lat["min"]),
        _tv(lat["max"]),
        _tv(lat["p95"]),
        _tv(lat["p99"]),
        _tv(m["bytes_sent"]),
        _tv(m["bytes_received"]),
        _errors_cell(m["errors"]),
    ]


def _checkin_tsv_row(report: dict[str, Any]) -> list[str]:
    metrics = report["metrics"]
    ic = metrics["initial_checkins"]
    pc = metrics["periodic_checkins"]
    ac = metrics["all_checkins"]
    cf = metrics["config_fetches"]
    lat = ac["latency_seconds"]
    bytes_sent = ac["bytes_sent"] + cf["bytes_sent"]
    bytes_received = ac["bytes_received"] + cf["bytes_received"]
    combined_errors: Counter[str] = Counter(ac["errors"]) + Counter(cf["errors"])
    return [
        report["run_id"],
        report["started_at"],
        _tv(report["configuration"]["requested_agents"]),
        _tv(report["enrolled_agents"]),
        _tv(report["configuration"]["num_check_ins_per_agent"]),
        _tv(ic["attempts"]),
        _tv(ic["successes"]),
        _tv(ic["failures"]),
        _tv(pc["attempts"]),
        _tv(pc["successes"]),
        _tv(pc["failures"]),
        _tv(ac["attempts"]),
        _tv(ac["successes"]),
        _tv(ac["failures"]),
        _tv(ac["success_rate_percent"]),
        _tv(ac["elapsed_seconds"]),
        _tv(ac["requests_per_second"]),
        _tv(lat["average"]),
        _tv(lat["median"]),
        _tv(lat["min"]),
        _tv(lat["max"]),
        _tv(lat["p95"]),
        _tv(lat["p99"]),
        _tv(cf["attempts"]),
        _tv(cf["successes"]),
        _tv(cf["failures"]),
        _tv(bytes_sent),
        _tv(bytes_received),
        _errors_cell(dict(combined_errors.most_common())),
    ]


def append_tsv_row(path: Path, headers: list[str], row: list[str]) -> None:
    """Write header if the file is new/empty, then append one data row."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or path.stat().st_size == 0
    with path.open("a", encoding="utf-8", newline="") as fh:
        if write_header:
            fh.write("\t".join(headers) + "\n")
        fh.write("\t".join(row) + "\n")


async def run_enrollment_batch(
    state: ScaleState, identities: list[Identity]
) -> list[VirtualAgent]:
    """Enroll a batch of identities concurrently; return only the successful agents."""
    semaphore = asyncio.Semaphore(ENROLLMENT_CONCURRENCY)
    enrolled: list[VirtualAgent] = []

    async def one(identity: Identity) -> None:
        async with semaphore:
            agent = await enroll_identity(state, identity)
        if agent is not None:
            enrolled.append(agent)

    await asyncio.gather(*(one(identity) for identity in identities))
    return enrolled


async def run_scale(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    limits = httpx.Limits(max_connections=None, max_keepalive_connections=0)
    async with httpx.AsyncClient(
        verify=args.ssl_context,
        timeout=httpx.Timeout(DEFAULT_TIMEOUT_SECONDS),
        limits=limits,
        http1=True,
        http2=False,
        follow_redirects=False,
    ) as client:
        state = ScaleState(args=args, run_id=args.run_id, client=client)
        return_code: int | None = None
        _report: dict[str, Any] = {}

        try:
            # --- Phase 1: enrollment with retries ---
            print(
                f"Starting enrollment blast: {args.num_of_agents:,} agents, "
                f"{ENROLLMENT_CONCURRENCY} concurrent requests, fresh connections"
            )
            identities = await generate_identities(args.num_of_agents, args.run_id)
            batch = await run_enrollment_batch(state, identities)
            state.agents.extend(batch)
            print(state.enrollment.progress_line("Enrollment round 1", args.num_of_agents))

            identity_offset = args.num_of_agents
            for retry_round in range(1, args.enrollment_retries + 1):
                shortfall = args.num_of_agents - len(state.agents)
                if shortfall <= 0:
                    break
                print(
                    f"Enrollment retry {retry_round}/{args.enrollment_retries}: "
                    f"{len(state.agents):,}/{args.num_of_agents:,} enrolled, "
                    f"need {shortfall:,} more..."
                )
                retry_identities = await generate_identities(
                    shortfall, args.run_id, offset=identity_offset
                )
                identity_offset += shortfall
                batch = await run_enrollment_batch(state, retry_identities)
                if not batch:
                    print(
                        f"Enrollment retry {retry_round}: zero new agents enrolled; "
                        f"stopping retries."
                    )
                    break
                state.agents.extend(batch)
                print(state.enrollment.progress_line(
                    f"Enrollment after retry {retry_round}", args.num_of_agents
                ))

            if not state.agents:
                state.checkins_done.set()
                print("No agents enrolled successfully; skipping check-ins.")
                return_code = 1
            else:
                shortfall = args.num_of_agents - len(state.agents)
                if shortfall:
                    print(
                        f"Enrollment complete with shortfall: "
                        f"{len(state.agents):,}/{args.num_of_agents:,} agents enrolled "
                        f"({shortfall:,} could not be recovered after "
                        f"{args.enrollment_retries} retries)."
                    )
                else:
                    print(
                        f"Enrollment complete: all {len(state.agents):,} agents enrolled."
                    )
                print(
                    f"Starting {args.num_check_ins:,} check-ins per agent, "
                    f"every {CHECKIN_INTERVAL_SECONDS:g} ± {CHECKIN_JITTER_SECONDS:g} seconds."
                )
                for agent in state.agents:
                    state.agent_tasks.append(asyncio.create_task(agent_loop(state, agent)))
                reporter = asyncio.create_task(minute_reporter(state))
                initial_reporter = asyncio.create_task(initial_checkin_reporter(state))
                await asyncio.gather(*state.agent_tasks)
                state.checkins_done.set()
                await asyncio.gather(reporter, initial_reporter)
        except asyncio.CancelledError:
            state.interrupted = True
            state.checkins_done.set()
            for task in state.agent_tasks:
                task.cancel()
            await asyncio.gather(*state.agent_tasks, return_exceptions=True)
            print("\nScale test interrupted; proceeding to report and cleanup.")
        finally:
            try:
                _, _, cleanup_completed = await cleanup_scale_connections(args, state.cleanup)
                if not cleanup_completed:
                    state.cleanup.record(
                        RequestResult(
                            ok=False,
                            latency=0,
                            status_code=None,
                            error="cleanup_cancelled",
                            sent_bytes=0,
                            received_bytes=0,
                            completed_at=time.monotonic(),
                        )
                    )
            except Exception as exc:
                print(f"Cleanup failed: {exc}")
                state.cleanup.record(
                    RequestResult(
                        ok=False,
                        latency=0,
                        status_code=None,
                        error=f"cleanup_error: {exc}",
                        sent_bytes=0,
                        received_bytes=0,
                        completed_at=time.monotonic(),
                    )
                )
            _report, report_path = save_report(state)
            print_final_report(_report, report_path)

        has_failures = any(
            bucket.failures
            for bucket in (
                state.enrollment,
                state.initial_checkins,
                state.periodic_checkins,
                state.config_fetches,
                state.cleanup,
            )
        )
        duplicates = duplicate_allocations(state.agents)
        has_duplicates = any(duplicates[field_name] for field_name in duplicates)
        if state.interrupted:
            return 130, _report
        if return_code is not None:
            return return_code, _report
        return (1 if has_failures or has_duplicates else 0), _report


def build_ssl_context(token_payload: dict[str, Any], ui_url: str) -> ssl.SSLContext:
    from logstashagent.tls_trust import build_ssl_context as agent_ssl_context
    from logstashagent.tls_trust import ensure_trust_from_token_payload

    ensure_trust_from_token_payload(ui_url, token_payload)
    return agent_ssl_context()


def _parse_increment_agents(value: str, parser: argparse.ArgumentParser) -> list[int]:
    try:
        parts = [int(p.strip()) for p in value.split(",")]
        if len(parts) != 3:
            raise ValueError("expected exactly 3 comma-separated values")
        start, end, step = parts
        if any(v <= 0 for v in (start, end, step)):
            raise ValueError("START, END, and STEP must all be positive integers")
        if start > end:
            raise ValueError("START must be less than or equal to END")
    except ValueError as exc:
        parser.error(f"--increment-agents: {exc} (format: START,END,STEP e.g. 10,200,10)")
    counts = list(range(start, end + 1, step))
    if not counts:
        parser.error("--increment-agents produced an empty range; check your START, END, and STEP values")
    return counts


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scale-test LogstashUI with wire-compatible virtual Logstash Agents."
    )
    agent_count_group = parser.add_mutually_exclusive_group()
    agent_count_group.add_argument("--num-of-agents", type=int, help="Number of virtual agents")
    agent_count_group.add_argument(
        "--increment-agents",
        metavar="START,END,STEP",
        help=(
            "Run sequential scale tests incrementing the agent count. "
            "Format: START,END,STEP (e.g. 10,200,10 runs at 10, 20, 30, ..., 200 agents)"
        ),
    )
    parser.add_argument(
        "--num-check-ins",
        type=int,
        help="Total check-ins per enrolled agent, including the immediate first check-in",
    )
    parser.add_argument("--enrollment-token", help="Base64-encoded enrollment token")
    parser.add_argument("--logstash-ui-url", required=True, help="LogstashUI base URL")
    parser.add_argument("--username", required=True, help="LogstashUI administrator username")
    parser.add_argument("--password", required=True, help="LogstashUI administrator password")
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Delete all LogstashUI agent connections whose names start with scale-test-",
    )
    parser.add_argument(
        "--yes", action="store_true", help="Skip the cleanup confirmation prompt"
    )
    parser.add_argument("--seed", type=int, default=20260825, help="Deterministic workload seed")
    parser.add_argument(
        "--enrollment-retries",
        type=int,
        default=3,
        help=(
            "Maximum number of additional enrollment rounds to run when the initial blast "
            "does not enroll all requested agents (default: 3; 0 disables retries)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "scale-test-results"),
        help="Directory for JSON reports",
    )
    args = parser.parse_args(argv)
    args.logstash_ui_url = args.logstash_ui_url.rstrip("/")
    args.run_id = utc_now().strftime("%Y%m%dT%H%M%SZ") + f"-{uuid.uuid4().hex[:6]}"

    if args.cleanup:
        return args

    if args.increment_agents:
        args.agent_counts = _parse_increment_agents(args.increment_agents, parser)
        args.num_of_agents = args.agent_counts[0]
    else:
        args.agent_counts = [args.num_of_agents] if args.num_of_agents is not None else []

    missing = [
        option
        for option, value in (
            ("--num-of-agents / --increment-agents", args.num_of_agents),
            ("--num-check-ins", args.num_check_ins),
            ("--enrollment-token", args.enrollment_token),
        )
        if value is None
    ]
    if missing:
        parser.error(f"the following arguments are required for a scale run: {', '.join(missing)}")
    if args.num_of_agents <= 0:
        parser.error("--num-of-agents must be greater than zero")
    if args.num_check_ins <= 0:
        parser.error("--num-check-ins must be greater than zero")
    return args


async def async_main(args: argparse.Namespace) -> int:
    if args.cleanup:
        # Cleanup uses ordinary session pooling; it is outside the measured workload.
        if args.enrollment_token:
            token_payload = decode_enrollment_token(args.enrollment_token)
            args.ssl_context = await asyncio.to_thread(
                build_ssl_context, token_payload, args.logstash_ui_url
            )
        else:
            args.ssl_context = ssl.create_default_context()
        deleted, failed, completed = await cleanup_scale_connections(args)
        if not completed:
            return 2
        return 1 if failed else 0

    token_payload = decode_enrollment_token(args.enrollment_token)
    args.ssl_context = await asyncio.to_thread(
        build_ssl_context, token_payload, args.logstash_ui_url
    )

    output_dir = Path(args.output_dir).resolve()
    sequence_id = utc_now().strftime("%Y%m%dT%H%M%SZ") + f"-{uuid.uuid4().hex[:6]}"
    enrollment_tsv = output_dir / f"scale-test-enrollment-{sequence_id}.tsv"
    checkin_tsv = output_dir / f"scale-test-checkins-{sequence_id}.tsv"

    def _append_tsv(report: dict[str, Any]) -> None:
        if not report:
            return
        append_tsv_row(enrollment_tsv, ENROLLMENT_TSV_HEADERS, _enrollment_tsv_row(report))
        append_tsv_row(checkin_tsv, CHECKIN_TSV_HEADERS, _checkin_tsv_row(report))

    if len(args.agent_counts) == 1:
        exit_code, report = await run_scale(args)
        _append_tsv(report)
        print(f"TSV enrollment : {enrollment_tsv}")
        print(f"TSV check-ins  : {checkin_tsv}")
        return exit_code

    overall_exit = 0
    for i, count in enumerate(args.agent_counts, 1):
        args.num_of_agents = count
        args.run_id = utc_now().strftime("%Y%m%dT%H%M%SZ") + f"-{uuid.uuid4().hex[:6]}"
        print(f"\n{'=' * 78}")
        print(f"INCREMENT RUN {i}/{len(args.agent_counts)}: {count:,} agents")
        print(f"{'=' * 78}")
        exit_code, report = await run_scale(args)
        _append_tsv(report)
        if exit_code not in (0, 130):
            overall_exit = exit_code
        if exit_code == 130:
            print("Increment sequence interrupted.")
            break
    print(f"\nTSV enrollment : {enrollment_tsv}")
    print(f"TSV check-ins  : {checkin_tsv}")
    return 130 if exit_code == 130 else overall_exit


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted before cleanup could complete. Run again with --cleanup.")
        return 130
    except Exception as exc:
        print(f"Scale test failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
