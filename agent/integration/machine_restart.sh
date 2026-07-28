#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $(uname -s) != Linux ]]; then
  echo "SKIP: Linux required"
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: root required"
  exit 0
fi
if [[ ${HUB_NET_MACHINE_RESTART_ACCEPTANCE:-} != 1 ]]; then
  echo "SKIP: set HUB_NET_MACHINE_RESTART_ACCEPTANCE=1"
  exit 0
fi

phase=${1:-}
state_file=/var/tmp/hub-net-machine-restart.acceptance
identity_path=/var/lib/hub-net/profile.identity
wireguard_path=/var/lib/hub-net/wireguard.key
unit=hub-net.service

require_installed_state() {
  [[ -x /usr/bin/hub-net ]] || {
    echo "FAIL: /usr/bin/hub-net is not installed"
    exit 1
  }
  [[ -f "$identity_path" && -f "$wireguard_path" ]] || {
    echo "FAIL: persistent identity and WireGuard key must exist before reboot"
    exit 1
  }
}

case "$phase" in
  prepare)
    require_installed_state
    [[ ! -e "$state_file" ]] || {
      echo "FAIL: pending acceptance state already exists: $state_file"
      exit 1
    }
    old_enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    old_active=$(systemctl is-active "$unit" 2>/dev/null || true)
    {
      printf 'boot_id=%q\n' "$(cat /proc/sys/kernel/random/boot_id)"
      printf 'identity_hash=%q\n' "$(sha256sum "$identity_path" | awk '{print $1}')"
      printf 'wireguard_hash=%q\n' "$(sha256sum "$wireguard_path" | awk '{print $1}')"
      printf 'version=%q\n' "$(/usr/bin/hub-net --version)"
      printf 'old_enabled=%q\n' "$old_enabled"
      printf 'old_active=%q\n' "$old_active"
    } >"$state_file"
    chmod 600 "$state_file"
    systemctl enable "$unit" >/dev/null
    echo "READY: reboot machine, then run verify phase"
    ;;
  verify)
    [[ -f "$state_file" ]] || {
      echo "FAIL: prepare phase state missing: $state_file"
      exit 1
    }
    # File contains only shell-quoted values generated above and is root-owned.
    [[ $(stat -c '%U:%a' "$state_file") == root:600 ]] || {
      echo "FAIL: invalid acceptance state ownership or mode"
      exit 1
    }
    source "$state_file"
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
    [[ "$current_boot_id" != "$boot_id" ]] || {
      echo "FAIL: machine has not rebooted since prepare phase"
      exit 1
    }
    require_installed_state
    [[ $(systemctl is-enabled "$unit") == enabled ]]
    [[ $(sha256sum "$identity_path" | awk '{print $1}') == "$identity_hash" ]]
    [[ $(sha256sum "$wireguard_path" | awk '{print $1}') == "$wireguard_hash" ]]
    [[ $(/usr/bin/hub-net --version) == "$version" ]]

    if [[ "$old_enabled" == enabled ]]; then
      systemctl enable "$unit" >/dev/null
    else
      systemctl disable "$unit" >/dev/null
    fi
    if [[ "$old_active" == active ]]; then
      systemctl start "$unit"
    else
      systemctl stop "$unit" >/dev/null 2>&1 || true
    fi
    unlink "$state_file"
    echo "PASS: installed agent identity and WireGuard key survived machine restart"
    ;;
  *)
    echo "usage: $0 prepare|verify"
    exit 2
    ;;
esac
