"""Group LiteLLM and Cisco AI Defense spans in one Galileo trace.

This adapter targets the pinned LiteLLM v1.108.0 image. Successful model calls
use a custom Galileo callback; pre-call blocks have no model span and are sent
directly by the guardrail. Guardrail spans never contain prompt or response text.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from litellm._logging import verbose_proxy_logger
from litellm.integrations.galileo import GALILEO_MAX_IN_MEMORY_RECORDS, GalileoObserve
from litellm.proxy.guardrails.guardrail_hooks.cisco_ai_defense.cisco_ai_defense import (
    CiscoAIDefenseGuardrail,
)


_EVENTS: queue.Queue[tuple[dict[str, object], str, str]] = queue.Queue(maxsize=1000)
_WORKER_LOCK = threading.Lock()
_WORKER: threading.Thread | None = None


def _session_external_id(data: dict[str, Any] | None) -> str:
    """Read the explicit OpenCode session header from LiteLLM request context."""
    if not isinstance(data, dict):
        return ""
    contexts = [data, data.get("litellm_params")]
    for context in contexts:
        if not isinstance(context, dict):
            continue
        sources = [context, context.get("proxy_server_request"), context.get("metadata")]
        for source in sources:
            if not isinstance(source, dict):
                continue
            headers = source.get("headers")
            if not isinstance(headers, dict):
                continue
            for name, value in headers.items():
                if str(name).lower() != "x-opencode-session-id":
                    continue
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", value):
                    return "opencode:" + value
    return ""


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
    session_external_id = _session_external_id(request_data)
    if session_external_id:
        payload["session_external_id"] = session_external_id
    return payload


def _enqueue(payload: dict[str, object], event_id: str, action: str) -> None:
    try:
        _EVENTS.put_nowait((payload, event_id, action))
        _start_worker()
    except queue.Full:
        verbose_proxy_logger.error("GALILEO_GUARDRAIL_TRACE_DROPPED event_id=%s queue_full", event_id)


def _utc_datetime(value: object) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return value.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _utc_iso(value: object) -> str:
    return _utc_datetime(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _call_id(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError):
        return ""


def _guardrail_events(standard_log: dict[str, Any]) -> list[dict[str, object]]:
    """Keep only Cisco decision metadata; the full response can contain PII."""
    events: list[dict[str, object]] = []
    for entry in standard_log.get("guardrail_information") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("guardrail_provider") != "cisco_ai_defense" and entry.get("guardrail_name") != "cisco-ai-defense":
            continue
        response = entry.get("guardrail_response") or {}
        if not isinstance(response, dict):
            response = {}
        raw_mode = entry.get("guardrail_mode")
        mode = str(getattr(raw_mode, "value", raw_mode) or "").rsplit(".", 1)[-1]
        direction = "input" if mode in ("pre_call", "during_call") else "output" if mode == "post_call" else "unknown"
        action = str(response.get("action") or ("error" if entry.get("guardrail_status") == "guardrail_failed_to_respond" else "allow"))
        classifications = response.get("classifications") or []
        rules = response.get("rules") or []
        rule_names = sorted(
            {
                str(rule["rule_name"])
                for rule in rules
                if isinstance(rule, dict)
                and rule.get("rule_name")
                and rule.get("classification") not in (None, "NONE_VIOLATION")
            }
        )
        events.append(
            {
                "direction": direction,
                "action": action,
                "is_safe": response.get("is_safe"),
                "classifications": [str(x) for x in classifications] if isinstance(classifications, list) else [],
                "rule_violations": rule_names,
                "severity": response.get("severity"),
                "event_id": str(response.get("event_id") or ""),
                "call_id": _call_id(response.get("client_transaction_id")),
                "created_at": _utc_iso(entry.get("start_time")),
                "duration_ns": max(0, int(float(entry.get("duration") or 0) * 1_000_000_000)),
            }
        )
    return events


def _append_guardrail_spans(trace: dict[str, object], record: dict[str, Any]) -> dict[str, object]:
    trace_id = str(trace["id"])
    spans = trace["spans"]
    if not isinstance(spans, list):
        return trace
    events = record.get("guardrail_events") or []
    for event in events:
        action = str(event["action"])
        direction = str(event["direction"])
        status = 503 if action == "error" else 400 if action == "block" else 200
        decision = {key: event[key] for key in (
            "action", "is_safe", "classifications", "rule_violations", "severity", "event_id"
        )}
        spans.append(
            {
                "type": "tool",
                "id": str(uuid.uuid4()),
                "trace_id": trace_id,
                "parent_id": trace_id,
                "name": f"Cisco AI Defense {direction}",
                "created_at": event["created_at"],
                "input": json.dumps({"call_id": event.get("call_id") or record.get("call_id", ""), "direction": direction}, separators=(",", ":")),
                "output": json.dumps(decision, separators=(",", ":")),
                "status_code": status,
                "metrics": {"duration_ns": event["duration_ns"]},
                "tags": ["cisco-ai-defense", action, direction],
            }
        )
    # The native Galileo span starts at the LiteLLM request start and covers
    # both guardrails. Place it in the interval when the model can run so the
    # trace reads input inspection -> model -> output inspection.
    model_span = next((span for span in spans if span.get("type") == "llm"), None)
    if model_span is not None:
        input_ends = [
            datetime.fromisoformat(str(event["created_at"]).replace("Z", "+00:00"))
            + timedelta(microseconds=int(event["duration_ns"]) / 1000)
            for event in events
            if event["direction"] == "input"
        ]
        output_starts = [
            datetime.fromisoformat(str(event["created_at"]).replace("Z", "+00:00"))
            for event in events
            if event["direction"] == "output"
        ]
        model_start = datetime.fromisoformat(str(model_span["created_at"]).replace("Z", "+00:00"))
        if input_ends:
            model_start = max(model_start, max(input_ends))
            model_span["created_at"] = _utc_iso(model_start)
        trace_start = datetime.fromisoformat(str(trace["created_at"]).replace("Z", "+00:00"))
        trace_end = trace_start + timedelta(milliseconds=int(record.get("latency_ms") or 0))
        model_end = min(output_starts) if output_starts else trace_end
        model_span["metrics"]["duration_ns"] = max(
            0, int((model_end - model_start).total_seconds() * 1_000_000_000)
        )
    spans.sort(key=lambda span: str(span.get("created_at", "")))
    return trace


class CorrelatedGalileoObserve(GalileoObserve):
    """Preserve Galileo's LLM trace and add Cisco spans to that same trace."""

    def __init__(self) -> None:
        super().__init__()
        self._flush_lock = asyncio.Lock()

    @staticmethod
    def _record_to_v2_trace(record: dict[str, Any]) -> dict[str, object]:
        trace = GalileoObserve._record_to_v2_trace(record)
        return _append_guardrail_spans(trace, record)

    async def flush_in_memory_records(self) -> None:
        """Quarantine a rejected trace instead of blocking all later exports."""
        async with self._flush_lock:
            while self.in_memory_records:
                # Galileo accepts one session_external_id per ingest request.
                # Send one record at a time so concurrent OpenCode sessions
                # cannot be grouped into each other's sessions.
                sent_records = [self.in_memory_records[0]]
                if not self.base_url or not self.project_id or not await self._ensure_headers():
                    verbose_proxy_logger.error("GALILEO_TRACE_EXPORT_FAILED missing Galileo configuration")
                    return
                if self.use_v2_api:
                    url = f"{self.base_url}/ingest/traces/{self.project_id}"
                else:
                    url = f"{self.base_url}/v2/projects/{self.project_id}/traces"
                payload = self._build_traces_payload(sent_records)
                session_external_id = sent_records[0].get("session_external_id")
                if session_external_id:
                    payload["session_external_id"] = session_external_id
                try:
                    response = await self.async_httpx_handler.post(
                        url=url, headers=self.headers, json=payload
                    )
                    status = response.status_code
                    error_body = response.text if status == 422 else ""
                except Exception as exc:
                    failed_response = getattr(exc, "response", None)
                    status = getattr(failed_response, "status_code", None)
                    error_body = failed_response.text if status == 422 else ""
                    if status != 422:
                        verbose_proxy_logger.error(
                            "GALILEO_TRACE_EXPORT_FAILED status=%s error_type=%s buffered=%s",
                            status, type(exc).__name__, len(self.in_memory_records),
                        )
                        return
                if 200 <= status < 300:
                    sent_ids = {id(record) for record in sent_records}
                    self.in_memory_records = [
                        record for record in self.in_memory_records if id(record) not in sent_ids
                    ]
                    continue
                if status != 422:
                    verbose_proxy_logger.error(
                        "GALILEO_TRACE_EXPORT_FAILED status=%s buffered=%s",
                        status, len(self.in_memory_records),
                    )
                    return
                match = re.search(r"trace (\d+)", error_body)
                index = int(match.group(1)) if match else 0
                index = index if index < len(sent_records) else 0
                rejected = sent_records[index]
                self.in_memory_records = [
                    record for record in self.in_memory_records if record is not rejected
                ]
                verbose_proxy_logger.error(
                    "GALILEO_TRACE_REJECTED status=422 call_id=%s buffered=%s",
                    rejected.get("call_id", ""), len(self.in_memory_records),
                )

    async def _async_log_success_event_impl(
        self, kwargs: dict[str, Any], response_obj: object, start_time: object, end_time: object
    ) -> None:
        if not self._is_configured():
            return
        standard_log = kwargs.get("standard_logging_object")
        if not isinstance(standard_log, dict):
            return
        input_text, output_text, messages = self._get_galileo_input_output_content(
            kwargs=kwargs, response_obj=response_obj
        )
        start = _utc_datetime(standard_log.get("startTime") or start_time)
        end = _utc_datetime(standard_log.get("endTime") or end_time)
        events = _guardrail_events(standard_log)
        call_id = next((str(e["call_id"]) for e in events if e.get("call_id")), "") or _call_id(standard_log.get("id"))
        if not output_text or not output_text.strip():
            output_text = "Assistant output unavailable to Galileo callback"
            verbose_proxy_logger.warning(
                "GALILEO_EMPTY_MODEL_OUTPUT call_id=%s response_type=%s",
                call_id, type(response_obj).__name__,
            )
        record: dict[str, Any] = {
            "latency_ms": max(0, int((end - start).total_seconds() * 1000)),
            "status_code": 200,
            "input_text": input_text,
            "output_text": output_text,
            "node_type": str(standard_log.get("call_type") or kwargs.get("call_type") or "litellm"),
            "model": str(standard_log.get("model") or kwargs.get("model") or "-"),
            "num_input_tokens": int(standard_log.get("prompt_tokens") or 0),
            "num_output_tokens": int(standard_log.get("completion_tokens") or 0),
            "num_total_tokens": int(standard_log.get("total_tokens") or 0),
            "cost": standard_log.get("response_cost"),
            "created_at": _utc_iso(start),
            "call_id": call_id,
            "session_external_id": _session_external_id(kwargs),
            "guardrail_events": events,
        }
        if isinstance(messages, dict):
            messages = messages.get("messages")
        if isinstance(messages, list) and messages:
            record["messages"] = messages
        self.in_memory_records.append(record)
        if len(self.in_memory_records) > GALILEO_MAX_IN_MEMORY_RECORDS:
            dropped = len(self.in_memory_records) - GALILEO_MAX_IN_MEMORY_RECORDS
            self.in_memory_records = self.in_memory_records[-GALILEO_MAX_IN_MEMORY_RECORDS:]
            verbose_proxy_logger.warning("Galileo guardrail logger dropped %s buffered record(s)", dropped)
        if len(self.in_memory_records) >= self.batch_size:
            await self.flush_in_memory_records()

    async def async_log_failure_event(
        self, kwargs: dict[str, Any], response_obj: object, start_time: object, end_time: object
    ) -> None:
        """Log failures after an LLM call; input blocks are emitted by the guardrail."""
        try:
            if not self._is_configured():
                return
            standard_log = kwargs.get("standard_logging_object")
            if not isinstance(standard_log, dict):
                return
            events = _guardrail_events(standard_log)
            if not events or any(e["direction"] == "input" and e["action"] in ("block", "error") for e in events):
                return
            call_id = next((str(e["call_id"]) for e in events if e.get("call_id")), "") or _call_id(standard_log.get("id"))
            start = _utc_datetime(standard_log.get("startTime") or start_time)
            end = _utc_datetime(standard_log.get("endTime") or end_time)
            blocked = any(e["action"] == "block" for e in events)
            record = {
                "latency_ms": max(0, int((end - start).total_seconds() * 1000)),
                "status_code": 400 if blocked else 500,
                "input_text": json.dumps({"call_id": call_id, "model": standard_log.get("model")}),
                "output_text": "Blocked by Cisco AI Defense" if blocked else "LLM request failed",
                "node_type": str(standard_log.get("call_type") or "litellm"),
                "model": str(standard_log.get("model") or "-"),
                "num_input_tokens": int(standard_log.get("prompt_tokens") or 0),
                "num_output_tokens": int(standard_log.get("completion_tokens") or 0),
                "num_total_tokens": int(standard_log.get("total_tokens") or 0),
                "cost": standard_log.get("response_cost"),
                "created_at": _utc_iso(start),
                "call_id": call_id,
                "session_external_id": _session_external_id(kwargs),
                "guardrail_events": events,
            }
            self.in_memory_records.append(record)
            await self.flush_in_memory_records()
        except Exception as exc:
            verbose_proxy_logger.error("GALILEO_CORRELATED_FAILURE_TRACE_FAILED error_type=%s", type(exc).__name__)


correlated_galileo = CorrelatedGalileoObserve()


class TracedCiscoAIDefenseGuardrail(CiscoAIDefenseGuardrail):
    """Retain Cisco's verdict handling and mirror sanitized decisions to Galileo."""

    def _log_decision(self, context: Any, verdict: Any, duration_ms: float, request_data: dict) -> None:
        super()._log_decision(context, verdict, duration_ms, request_data)
        # Successful calls are exported once by CorrelatedGalileoObserve with
        # input, LLM, and output spans under the same trace. A pre-call block
        # has no LLM success callback, so export its guardrail-only trace here.
        if context.direction != "input" or verdict.action != "block":
            return
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
        if direction != "input" or self.fallback_on_error != "block":
            return super()._handle_api_error(
                error,
                request_data=request_data,
                start_time=start_time,
                surface=surface,
                direction=direction,
            )
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
