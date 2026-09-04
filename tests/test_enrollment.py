#Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
#or more contributor license agreements. Licensed under the Elastic License;
#you may not use this file except in compliance with the Elastic License.

"""Tests for logstashagent.enrollment."""

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from logstashagent import enrollment


def _encoded_token(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


class TestGetHostname:
    def test_returns_socket_hostname(self):
        with patch.object(enrollment.socket, "gethostname", return_value="my-box"):
            assert enrollment.get_hostname() == "my-box"

    def test_unknown_host_on_error(self):
        with patch.object(
            enrollment.socket,
            "gethostname",
            side_effect=OSError("no name"),
        ):
            assert enrollment.get_hostname() == "unknown-host"


class TestGetCallbackHost:
    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LOGSTASH_AGENT_CALLBACK_HOST", "agent.example.com")
        assert enrollment.get_callback_host() == "agent.example.com"

    def test_prefers_ip_over_hostname(self, monkeypatch):
        """IP first: Docker LogstashUI cannot rely on host DNS."""
        monkeypatch.delenv("LOGSTASH_AGENT_CALLBACK_HOST", raising=False)
        monkeypatch.delenv("LOGSTASH_AGENT_HOSTNAME", raising=False)
        monkeypatch.setattr(
            enrollment,
            "_non_loopback_ipv4s",
            lambda: ["10.0.0.5"],
        )
        monkeypatch.setattr(enrollment.socket, "getfqdn", lambda: "loggy.untergeek.net")
        assert enrollment.get_callback_host() == "10.0.0.5"

    def test_uses_ip_when_available(self, monkeypatch):
        monkeypatch.delenv("LOGSTASH_AGENT_CALLBACK_HOST", raising=False)
        monkeypatch.delenv("LOGSTASH_AGENT_HOSTNAME", raising=False)
        monkeypatch.setattr(enrollment, "_non_loopback_ipv4s", lambda: ["10.9.5.31"])
        monkeypatch.setattr(enrollment.socket, "getfqdn", lambda: "loggy")
        assert enrollment.get_callback_host() == "10.9.5.31"

    def test_falls_back_to_fqdn_when_no_ip(self, monkeypatch):
        monkeypatch.delenv("LOGSTASH_AGENT_CALLBACK_HOST", raising=False)
        monkeypatch.delenv("LOGSTASH_AGENT_HOSTNAME", raising=False)
        monkeypatch.setattr(enrollment, "_non_loopback_ipv4s", lambda: [])
        monkeypatch.setattr(enrollment.socket, "getfqdn", lambda: "loggy.untergeek.net")
        assert enrollment.get_callback_host() == "loggy.untergeek.net"

    def test_get_callback_ip(self, monkeypatch):
        monkeypatch.setattr(enrollment, "_non_loopback_ipv4s", lambda: ["10.1.2.3"])
        assert enrollment.get_callback_ip() == "10.1.2.3"
        monkeypatch.setattr(enrollment, "_non_loopback_ipv4s", lambda: [])
        assert enrollment.get_callback_ip() is None

    def test_short_host_label(self):
        assert enrollment.short_host_label("loggy.untergeek.net") == "loggy"
        assert enrollment.short_host_label("10.0.0.1") == "10.0.0.1"

    def test_display_host_label_uses_hostname_for_ip(self, monkeypatch):
        monkeypatch.setattr(enrollment, "get_hostname", lambda: "loggy")
        assert enrollment.display_host_label("10.9.5.31") == "loggy"
        assert enrollment.display_host_label("loggy.untergeek.net") == "loggy"


class TestDecodeEnrollmentToken:
    def test_decodes_valid_payload(self):
        payload = {"enrollment_token": "secret-inner", "extra": 1}
        encoded = _encoded_token(payload)

        out = enrollment.decode_enrollment_token(encoded)

        assert out == payload

    def test_missing_enrollment_token_raises(self):
        encoded = _encoded_token({"other": "x"})

        with pytest.raises(ValueError, match="Failed to decode enrollment token"):
            enrollment.decode_enrollment_token(encoded)

    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Failed to decode enrollment token"):
            enrollment.decode_enrollment_token("@@@not-base64!!!")

    def test_invalid_json_raises(self):
        raw = base64.b64encode(b"not-json").decode("ascii")

        with pytest.raises(ValueError, match="Failed to decode enrollment token"):
            enrollment.decode_enrollment_token(raw)


class TestEnrollAgent:
    def test_posts_and_returns_result(self):
        token_payload = {"enrollment_token": "inner"}
        encoded = _encoded_token(token_payload)
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        response.text = "{}"
        result_body = {
            "success": True,
            "api_key": "ak",
            "policy_id": 9,
            "connection_id": 42,
            "policy_config": {},
        }
        response.json.return_value = result_body

        with patch.object(
            enrollment, "get_callback_host", return_value="host-1.example.com"
        ), patch.object(
            enrollment, "get_callback_ip", return_value="10.0.0.9"
        ), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=True
        ), patch.object(enrollment.requests, "post", return_value=response) as post:
            out = enrollment.enroll_agent(
                encoded, "https://ui.example.com", "agent-uuid"
            )

        assert out == result_body
        post.assert_called_once()
        args, kwargs = post.call_args
        assert args[0] == "https://ui.example.com/ConnectionManager/Enroll/"
        body = kwargs["json"]
        assert body["enrollment_token"] == encoded
        assert body["host"] == "host-1.example.com"
        assert body["host_short"] == "host-1"
        assert body["callback_ip"] == "10.0.0.9"
        assert body["agent_id"] == "agent-uuid"
        assert "csr_pem" in body
        assert "BEGIN CERTIFICATE REQUEST" in body["csr_pem"]
        assert kwargs["timeout"] == 30
        assert kwargs["verify"] is True

    def test_success_false_raises(self):
        encoded = _encoded_token({"enrollment_token": "x"})
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        response.json.return_value = {"success": False, "error": "nope"}

        with patch.object(enrollment, "get_callback_host", return_value="h"), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=True
        ), patch.object(enrollment.requests, "post", return_value=response):
            with pytest.raises(Exception, match="Enrollment failed: nope"):
                enrollment.enroll_agent(encoded, "http://localhost", "aid")

    def test_non_json_response_raises(self):
        encoded = _encoded_token({"enrollment_token": "x"})
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        response.text = "<html>not json</html>"
        response.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

        with patch.object(enrollment, "get_callback_host", return_value="h"), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=True
        ), patch.object(enrollment.requests, "post", return_value=response):
            with pytest.raises(Exception, match="Server returned non-JSON response"):
                enrollment.enroll_agent(encoded, "http://localhost:8000", "aid")

    def test_request_exception_wrapped(self):
        encoded = _encoded_token({"enrollment_token": "x"})
        with patch.object(enrollment, "get_callback_host", return_value="h"), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=True
        ), patch.object(
            enrollment.requests,
            "post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            with pytest.raises(Exception, match="Failed to connect to logstashui"):
                enrollment.enroll_agent(encoded, "http://down", "aid")

    def test_http_ui_omits_csr_pem(self, monkeypatch):
        encoded = _encoded_token({"enrollment_token": "x"})
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        response.headers = {}
        response.text = "{}"
        response.json.return_value = {
            "success": True,
            "api_key": "ak",
            "policy_id": 1,
            "connection_id": 1,
            "policy_config": {},
        }
        with patch.object(enrollment, "get_callback_host", return_value="h"), patch.object(
            enrollment, "get_callback_ip", return_value=None
        ), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=False
        ), patch.object(enrollment.requests, "post", return_value=response) as post:
            enrollment.enroll_agent(encoded, "http://ui.example.com", "aid")
        body = post.call_args.kwargs["json"]
        assert "csr_pem" not in body
        assert post.call_args.kwargs["verify"] is False

    def test_tls_env_false_omits_csr_pem(self, monkeypatch):
        monkeypatch.setenv("LOGSTASH_AGENT_TLS", "false")
        encoded = _encoded_token({"enrollment_token": "x"})
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        response.headers = {}
        response.text = "{}"
        response.json.return_value = {
            "success": True,
            "api_key": "ak",
            "policy_id": 1,
            "connection_id": 1,
            "policy_config": {},
        }
        with patch.object(enrollment, "get_callback_host", return_value="h"), patch.object(
            enrollment, "get_callback_ip", return_value=None
        ), patch(
            "logstashagent.tls_trust.ensure_trust_from_token_payload", return_value=None
        ), patch(
            "logstashagent.tls_trust.ssl_verify_argument", return_value=True
        ), patch.object(enrollment.requests, "post", return_value=response) as post:
            enrollment.enroll_agent(encoded, "https://ui.example.com", "aid")
        assert "csr_pem" not in post.call_args.kwargs["json"]


class TestComputeHash:
    def test_sha256_hex(self):
        assert enrollment.compute_hash("hello") == hashlib.sha256(
            b"hello"
        ).hexdigest()


class TestSaveEnrollmentConfig:
    def test_updates_agent_state(self):
        policy = {"settings_path": "/etc/logstash", "logs_path": "/var/log"}

        with patch.object(enrollment.agent_state, "update_state") as upd:
            enrollment.save_enrollment_config(
                api_key="key",
                logstash_ui_url="http://ui",
                policy_id=3,
                connection_id=7,
                policy_config=policy,
            )

        calls = [c[0] for c in upd.call_args_list]
        # Core enrollment fields must be present; additive mode/policy fields may follow.
        assert ("enrolled", True) in calls
        assert ("logstash_ui_url", "http://ui") in calls
        assert ("api_key", "key") in calls
        assert ("policy_id", 3) in calls
        assert ("connection_id", 7) in calls
        assert ("settings_path", "/etc/logstash") in calls
        assert ("logs_path", "/var/log") in calls
        assert ("binary_path", None) in calls
        assert ("revision_number", 0) in calls
        # Missing policy_type defaults to PACKAGED / mode packaged
        assert ("policy_type", "PACKAGED") in calls
        assert ("mode", "packaged") in calls
        assert ("policy_config", policy) in calls

    def test_simulate_saves_policy_blob_and_pending_flag(self):
        policy = {
            "policy_type": "SIMULATE",
            "instance_id": 2,
            "settings_path": "/opt/logstash-agent/simulate-2/settings",
            "logs_path": "/opt/logstash-agent/simulate-2/logs",
        }

        with patch.object(enrollment.agent_state, "update_state") as upd:
            enrollment.save_enrollment_config(
                api_key="key",
                logstash_ui_url="http://ui",
                policy_id=3,
                connection_id=7,
                policy_config=policy,
            )

        calls = [c[0] for c in upd.call_args_list]
        assert ("mode", "simulate") in calls
        assert ("policy_type", "SIMULATE") in calls
        assert ("policy_config", policy) in calls
        assert ("simulate_setup_pending", True) in calls
        assert ("instance_id", 2) in calls

    def test_persists_logstash_via_ui(self):
        """
        Enrollment is one of the three channels carrying the flag. Dropping it
        means the agent pulls from Elastic until the first check-in lands.
        """
        policy = {
            "policy_type": "SIMULATE",
            "logstash_source": "VERSION",
            "logstash_version": "9.4.3",
            "logstash_via_ui": True,
        }

        with patch.object(enrollment.agent_state, "update_state") as upd:
            enrollment.save_enrollment_config(
                api_key="key",
                logstash_ui_url="http://ui",
                policy_id=3,
                connection_id=7,
                policy_config=policy,
            )

        calls = [c[0] for c in upd.call_args_list]
        assert ("logstash_via_ui", True) in calls

    def test_via_ui_false_is_persisted(self):
        """False must be written too — a PACKAGED policy has to clear a stale True."""
        policy = {"policy_type": "PACKAGED", "logstash_via_ui": False}

        with patch.object(enrollment.agent_state, "update_state") as upd:
            enrollment.save_enrollment_config(
                api_key="key",
                logstash_ui_url="http://ui",
                policy_id=3,
                connection_id=7,
                policy_config=policy,
            )

        calls = [c[0] for c in upd.call_args_list]
        assert ("logstash_via_ui", False) in calls

    def test_via_ui_absent_is_not_written(self):
        policy = {"settings_path": "/etc/logstash"}

        with patch.object(enrollment.agent_state, "update_state") as upd:
            enrollment.save_enrollment_config(
                api_key="key",
                logstash_ui_url="http://ui",
                policy_id=3,
                connection_id=7,
                policy_config=policy,
            )

        keys = [c[0][0] for c in upd.call_args_list]
        assert "logstash_via_ui" not in keys

    def test_propagates_update_state_failure(self):
        with patch.object(
            enrollment.agent_state,
            "update_state",
            side_effect=OSError("disk full"),
        ):
            with pytest.raises(Exception, match="Failed to save enrollment configuration"):
                enrollment.save_enrollment_config(
                    "k",
                    "http://x",
                    1,
                    2,
                    {},
                )


class TestPerformEnrollment:
    def test_full_flow(self):
        encoded = _encoded_token({"enrollment_token": "t"})
        enroll_result = {
            "success": True,
            "api_key": "long-api-key-value",
            "policy_id": 1,
            "connection_id": 2,
            "policy_config": {"settings_path": "/s", "logs_path": "/l"},
        }

        with patch.object(enrollment, "enroll_agent", return_value=enroll_result):
            with patch.object(enrollment, "save_enrollment_config") as save:
                out = enrollment.perform_enrollment(
                    encoded, "https://example.com", "agent-1"
                )

        assert out == enroll_result
        save.assert_called_once_with(
            api_key="long-api-key-value",
            logstash_ui_url="https://example.com",
            policy_id=1,
            connection_id=2,
            policy_config={"settings_path": "/s", "logs_path": "/l"},
        )

    def test_simulate_setup_complete_clears_pending(self):
        encoded = _encoded_token({"enrollment_token": "t"})
        policy_config = {
            "policy_type": "SIMULATE",
            "instance_id": 3,
            "settings_path": "/opt/logstash-agent/simulate-3/settings",
            "logs_path": "/opt/logstash-agent/simulate-3/logs",
        }
        enroll_result = {
            "success": True,
            "api_key": "long-api-key-value",
            "policy_id": 1,
            "connection_id": 2,
            "policy_config": policy_config,
        }
        setup_out = {
            "status": "complete",
            "via": "root",
            "messages": ["ok"],
        }

        with patch.object(enrollment, "enroll_agent", return_value=enroll_result):
            with patch.object(enrollment, "save_enrollment_config"):
                with patch(
                    "logstashagent.installer.ensure_simulate_setup",
                    return_value=setup_out,
                ) as ensure:
                    with patch.object(
                        enrollment.agent_state, "update_state"
                    ) as upd:
                        out = enrollment.perform_enrollment(
                            encoded, "https://example.com", "agent-1"
                        )

        ensure.assert_called_once_with(policy_config)
        assert out["simulate_setup"] == setup_out
        upd.assert_any_call("simulate_setup_pending", False)

    def test_simulate_setup_pending_keeps_flag(self):
        encoded = _encoded_token({"enrollment_token": "t"})
        policy_config = {
            "policy_type": "SIMULATE",
            "instance_id": 5,
            "settings_path": "/opt/logstash-agent/simulate-5/settings",
            "logs_path": "/opt/logstash-agent/simulate-5/logs",
        }
        enroll_result = {
            "success": True,
            "api_key": "long-api-key-value",
            "policy_id": 1,
            "connection_id": 2,
            "policy_config": policy_config,
        }
        setup_out = {
            "status": "pending",
            "via": "deferred",
            "messages": ["need root"],
        }

        with patch.object(enrollment, "enroll_agent", return_value=enroll_result):
            with patch.object(enrollment, "save_enrollment_config"):
                with patch(
                    "logstashagent.installer.ensure_simulate_setup",
                    return_value=setup_out,
                ):
                    with patch.object(
                        enrollment.agent_state, "update_state"
                    ) as upd:
                        out = enrollment.perform_enrollment(
                            encoded, "https://example.com", "agent-1"
                        )

        assert out["simulate_setup"]["status"] == "pending"
        upd.assert_any_call("simulate_setup_pending", True)

    def test_re_raises_on_enroll_failure(self):
        encoded = _encoded_token({"enrollment_token": "t"})

        with patch.object(
            enrollment,
            "enroll_agent",
            side_effect=Exception("network"),
        ):
            with pytest.raises(Exception, match="network"):
                enrollment.perform_enrollment(encoded, "http://x", "aid")
