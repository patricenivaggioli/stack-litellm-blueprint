"""Send Cisco AI Defense decisions to Galileo without changing enforcement.

This adapter targets the Cisco guardrail in the pinned LiteLLM v1.108.0 image.
It emits one standalone Galileo trace per inspection, linked to LiteLLM logs by
call_id. No prompt, model response, Cisco explanation, or credential is sent.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from litellm._logging import verbose_proxy_logger
from litellm.proxy.guardrails.guardrail_hooks.cisco_ai_defense.cisco_ai_defense import (
    CiscoAIDefenseGuardrail,
)


_EVENTS: queue.Queue[tuple[dict[str, object], str, str]] = queue.Queue(maxsize=1000)
_WORKER_LOCK = threading.Lock()
_WORKER: threading.Thread | None = None


def _worker() -> None:
    while True:
        payload, event_id, action = _EVENTS.get()
        try:
            _send(payload, event_id, action)
        except Exception as exc:
            verbose_proxy_logger.error(
                "GALILEO_GUARDRAIL_TRACE_FAILED event_id=%s error_type=%s",
                event_id,
                type(exc).__name__,
            )
        finally:
            _EVENTS.task_done()


def _start_worker() -> None:
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = threading.Thread(target=_worker, name="galileo-guardrail-traces", daemon=True)
            _WORKER.start()


def _send(payload: dict[str, object], event_id: str, action: str) -> None:
    api_key = os.environ.get("GALILEO_API_KEY")
    project_id = os.environ.get("GALILEO_PROJECT_ID")
    if not api_key or not project_id:
        verbose_proxy_logger.warning("GALILEO_GUARDRAIL_TRACE_SKIPPED missing Galileo configuration")
        return

    base_url = (os.environ.get("GALILEO_BASE_URL") or "https://api.galileo.ai").rstrip("/")
    url = f"{base_url}/ingest/traces/{project_id}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "Galileo-API-Key": api_key},
        method="POST",
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                response.read()
            verbose_proxy_logger.info(
                "GALILEO_GUARDRAIL_TRACE_SENT event_id=%s action=%s", event_id, action
            )
            return
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504):
                verbose_proxy_logger.error(
                    "GALILEO_GUARDRAIL_TRACE_FAILED event_id=%s status=%s", event_id, exc.code
                )
                return
            status = str(exc.code)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            status = type(exc).__name__
        if attempt < 2:
            time.sleep(2**attempt)
    verbose_proxy_logger.error(
        "GALILEO_GUARDRAIL_TRACE_FAILED event_id=%s status=%s", event_id, status
    )


def _trace_payload(
    *,
    guardrail_name: str,
    surface: str,
    direction: str,
    action: str,
    status_code: int,
    duration_ms: float,
    request_data: dict[str, Any] | None,
    decision: dict[str, object],
) -> dict[str, object]:
    request_data = request_data or {}
    trace_id = str(uuid.uuid4())
    span_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    context = {
        "call_id": str(request_data.get("litellm_call_id") or ""),
        "model": str(request_data.get("model") or ""),
        "surface": surface,
        "direction": direction,
    }
    input_text = json.dumps(context, separators=(",", ":"))
    output_text = json.dumps(decision, separators=(",", ":"))
    duration_ns = max(0, int(duration_ms * 1_000_000))
    span = {
        "type": "tool",
        "id": span_id,
        "trace_id": trace_id,
        "parent_id": trace_id,
        "name": guardrail_name,
        "created_at": created_at,
        "input": input_text,
        "output": output_text,
        "status_code": status_code,
        "metrics": {"duration_ns": duration_ns},
        "tags": ["cisco-ai-defense", action, direction],
    }
    trace = {
        "type": "trace",
        "id": trace_id,
        "name": f"{guardrail_name} {direction}",
        "created_at": created_at,
        "input": input_text,
        "output": output_text,
        "status_code": status_code,
        "metrics": {"duration_ns": duration_ns},
        "spans": [span],
    }
    payload: dict[str, object] = {
        "traces": [trace],
        "logging_method": "api_direct",
        "reliable": False,
        "is_complete": True,
    }
    stream_id = os.environ.get("GALILEO_LOG_STREAM_ID")
    if stream_id:
        payload["log_stream_id"] = stream_id
    return payload


def _enqueue(payload: dict[str, object], event_id: str, action: str) -> None:
    try:
        _EVENTS.put_nowait((payload, event_id, action))
        _start_worker()
    except queue.Full:
        verbose_proxy_logger.error("GALILEO_GUARDRAIL_TRACE_DROPPED event_id=%s queue_full", event_id)


class TracedCiscoAIDefenseGuardrail(CiscoAIDefenseGuardrail):
    """Retain Cisco's verdict handling and mirror sanitized decisions to Galileo."""

    def _log_decision(self, context: Any, verdict: Any, duration_ms: float, request_data: dict) -> None:
        super()._log_decision(context, verdict, duration_ms, request_data)
        try:
            rules = sorted(
                {
                    str(rule["rule_name"])
                    for rule in verdict.rules
                    if isinstance(rule, dict)
                    and rule.get("rule_name")
                    and rule.get("classification") not in (None, "NONE_VIOLATION")
                }
            )
            action = str(verdict.action or "allow")
            event_id = str(verdict.event_id or "")
            decision = {
                "action": action,
                "is_safe": verdict.is_safe,
                "classifications": list(verdict.classifications or []),
                "rule_violations": rules,
                "severity": verdict.severity,
                "event_id": event_id,
            }
            payload = _trace_payload(
                guardrail_name=self.guardrail_name,
                surface=context.surface,
                direction=context.direction,
                action=action,
                status_code=400 if action == "block" else 200,
                duration_ms=duration_ms,
                request_data=request_data,
                decision=decision,
            )
            _enqueue(payload, event_id, action)
        except Exception as exc:
            verbose_proxy_logger.error(
                "GALILEO_GUARDRAIL_TRACE_FAILED error_type=%s", type(exc).__name__
            )

    def _handle_api_error(
        self,
        error: Exception,
        *,
        request_data: dict | None = None,
        start_time: datetime | None = None,
        surface: str = "chat",
        direction: str = "input",
    ) -> dict[str, object]:
        try:
            duration_ms = (
                max(0.0, (datetime.now(start_time.tzinfo) - start_time).total_seconds() * 1000)
                if start_time is not None
                else 0.0
            )
            decision = {
                "action": "error",
                "error_type": type(error).__name__,
                "fallback_on_error": self.fallback_on_error,
            }
            payload = _trace_payload(
                guardrail_name=self.guardrail_name,
                surface=surface,
                direction=direction,
                action="error",
                status_code=503 if self.fallback_on_error == "block" else 200,
                duration_ms=duration_ms,
                request_data=request_data,
                decision=decision,
            )
            _enqueue(payload, "", "error")
        except Exception as exc:
            verbose_proxy_logger.error(
                "GALILEO_GUARDRAIL_TRACE_FAILED error_type=%s", type(exc).__name__
            )
        return super()._handle_api_error(
            error,
            request_data=request_data,
            start_time=start_time,
            surface=surface,
            direction=direction,
        )
