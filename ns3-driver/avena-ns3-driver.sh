#!/usr/bin/env bash
set -euo pipefail

NS3_ROOT="${AVENA_NS3_ROOT:-${NS3_ROOT:-}}"
if [[ -z "${NS3_ROOT}" ]]; then
  echo "AVENA_NS3_ROOT (or NS3_ROOT) must point to an ns-3 checkout" >&2
  exit 2
fi

DRIVER_NAME="scratch/avena-ns3-driver"

quoted_args=()
for arg in "$@"; do
  quoted_args+=("$(printf '%q' "$arg")")
done

exec "${NS3_ROOT}/ns3" run "${DRIVER_NAME} -- ${quoted_args[*]}"
