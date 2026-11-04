#!/usr/bin/env bash
set -euo pipefail

route_name="${1:?route name is required}"
namespace="${2:?namespace is required}"

for attempt in {1..60}; do
  host="$(kubectl get route "$route_name" -n "$namespace" -o jsonpath='{.status.ingress[0].host}' 2>/dev/null || true)"
  admitted="$(kubectl get route "$route_name" -n "$namespace" -o jsonpath='{.status.ingress[0].conditions[?(@.type=="Admitted")].status}' 2>/dev/null || true)"
  if [[ -n "$host" && "$admitted" == "True" ]]; then
    export route_url="https://${host}"
    echo "route_url=${route_url}"
    exit 0
  fi
  sleep 2
done

echo "Route ${route_name} in namespace ${namespace} was not admitted" >&2
exit 1
