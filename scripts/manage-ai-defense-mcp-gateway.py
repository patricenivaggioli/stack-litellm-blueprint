#!/usr/bin/env python3
"""Manage one AI Defense MCPGateway connection owned by a Torque environment.

Only non-secret output assignments are printed on successful deploy so Torque
can capture them as shell-grain command outputs.
"""

import json
import os
import re
import shlex
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse


UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NAME = re.compile(r"^stack-mcp-[a-z0-9-]{8,80}$")


def field(obj, *names):
    if not isinstance(obj, dict):
        return None
    for name in names:
        if name in obj:
            return obj[name]
    return None


def required_environment(mode):
    name = os.environ.get("MCP_CONNECTION_NAME", "")
    base = os.environ.get("AI_DEFENSE_API_BASE", "").rstrip("/")
    key = os.environ.get("AI_DEFENSE_MANAGEMENT_KEY", "")
    if not NAME.fullmatch(name):
        raise ValueError("MCP_CONNECTION_NAME must be a Torque-owned stack-mcp name")
    parsed = urlparse(base)
    if (parsed.scheme != "https" or parsed.hostname not in
            ("api.security.cisco.com", "us.api.security.cisco.com", "eu.api.security.cisco.com") or
            parsed.path != "/api/ai-defense/v1" or parsed.username or parsed.password or
            parsed.query or parsed.fragment or not key):
        raise ValueError("Use a Cisco AI Defense HTTPS Management API base and management API key")
    ids = [item.strip() for item in os.environ.get("MCP_SERVER_IDS", "").split(",") if item.strip()]
    idp = os.environ.get("DUO_IDP_ID", "").strip()
    connector = os.environ.get("AI_DEFENSE_CONNECTOR_ID", "").strip()
    if mode == "deploy":
        if not ids or len(set(ids)) != len(ids) or any(not UUID.fullmatch(item) for item in ids):
            raise ValueError("MCP_SERVER_IDS must contain unique registered UUIDs")
        if not UUID.fullmatch(idp):
            raise ValueError("DUO_IDP_ID must be an AI Defense IdP UUID")
        if connector and not UUID.fullmatch(connector):
            raise ValueError("AI_DEFENSE_CONNECTOR_ID must be a UUID when provided")
    return name, base, key, ids, idp, connector


def request(base, key, method, path, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"X-Cisco-AI-Defense-Tenant-API-Key": key, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        # The API response can contain sensitive connection details; do not log it.
        raise RuntimeError("AI Defense Management API returned HTTP %s for %s %s" % (exc.code, method, path)) from None


def connections(base, key, name):
    result = request(base, key, "POST", "/resource/connections/filter", {
        "connection_name": name,
        "connection_type": "MCPGateway",
        "limit": 100,
        "offset": 0,
    })
    wrapper = field(result, "connections")
    items = field(wrapper, "items") if isinstance(wrapper, dict) else wrapper
    if items is None:
        items = field(result, "items")
    if not isinstance(items, list):
        raise RuntimeError("Unexpected AI Defense connection-list response")
    return [item for item in items if field(item, "connection_name", "connectionName") == name]


def connection_id(item):
    return field(item, "connection_id", "connectionId")


def deploy(name, base, key, ids, idp, connector):
    matches = connections(base, key, name)
    if len(matches) > 1:
        raise RuntimeError("More than one MCPGateway connection has the Torque environment name")
    if matches:
        current = matches[0]
        conn_id = connection_id(current)
    else:
        body = {
            "connection_name": name,
            "connection_type": "MCPGateway",
            "resource_ids": ids,
            "inbound_auth": {"protected": True, "idp_id": idp},
        }
        if connector:
            body["connector_id"] = connector
        created = request(base, key, "POST", "/resource/connections", body)
        conn_id = connection_id(created)
    if not isinstance(conn_id, str) or not UUID.fullmatch(conn_id):
        raise RuntimeError("AI Defense did not return a connection UUID")
    current = None
    for _ in range(5):
        result = request(base, key, "GET", "/resource/connections/" + quote(conn_id))
        current = field(result, "connection") or result
        proxy = field(current, "proxy_url", "proxyUrl")
        if proxy:
            break
        time.sleep(2)
    if not proxy or not isinstance(proxy, str) or not proxy.startswith("https://"):
        raise RuntimeError("Connection was created but AI Defense has not returned its HTTPS proxy URL")
    auth = field(current, "inbound_auth", "inboundAuth") or {}
    existing_idp = field(auth, "idp_id", "idpId")
    if existing_idp and existing_idp != idp:
        raise RuntimeError("Existing connection has a different Duo IdP; refusing to adopt it")
    resources = field(current, "resource_ids", "resourceIds")
    if resources is not None and set(resources) != set(ids):
        raise RuntimeError("Existing connection has different MCP servers; refusing to adopt it")
    print("export connection_id=" + shlex.quote(conn_id))
    print("export proxy_url=" + shlex.quote(proxy))


def destroy(name, base, key):
    matches = connections(base, key, name)
    if len(matches) > 1:
        raise RuntimeError("Multiple matching connections; refusing to delete")
    if not matches:
        return
    conn_id = connection_id(matches[0])
    if not isinstance(conn_id, str) or not UUID.fullmatch(conn_id):
        raise RuntimeError("Matching connection has no valid UUID; refusing to delete")
    request(base, key, "DELETE", "/resource/connections/" + quote(conn_id))


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("deploy", "destroy"):
        raise ValueError("Usage: manage-ai-defense-mcp-gateway.py deploy|destroy")
    mode = sys.argv[1]
    args = required_environment(mode)
    if mode == "deploy":
        deploy(*args)
    else:
        destroy(*args[:3])


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, urllib.error.URLError) as exc:
        print("MCP gateway provisioning failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
