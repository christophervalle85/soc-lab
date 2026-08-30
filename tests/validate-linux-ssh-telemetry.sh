#!/usr/bin/env bash

set -uo pipefail

target_ip="${1:-192.168.132.30}"
test_user="${2:-soclab_l5_test}"

echo "Generating one controlled SSH authentication failure."
echo "Target: ${target_ip}"
echo "Nonexistent test user: ${test_user}"

output="$({
  ssh \
    -o ConnectTimeout=7 \
    -o PreferredAuthentications=none \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=no \
    "${test_user}@${target_ip}" true
} 2>&1)"
status=$?

printf '%s\n' "$output"

if [[ $status -eq 0 ]]; then
  echo "ERROR: The nonexistent test account authenticated unexpectedly." >&2
  exit 1
fi

if [[ "$output" == *"Permission denied"* ]]; then
  echo "Local validation: PASS (the controlled login was rejected)."
  echo "Next: search Wazuh Threat Hunting for ${test_user} on agent SOC-UBUNTU."
  exit 0
fi

echo "WARNING: SSH failed, but not with the expected permission-denied result." >&2
echo "Confirm that soc-ubuntu is online and TCP port 22 is reachable." >&2
exit 2
