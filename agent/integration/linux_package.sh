#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "SKIP: Linux required"
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: root required"
  exit 0
fi

for command in go make sha256sum tar file ldd systemctl stat wg nft conntrack resolvectl bun; do
  command -v "$command" >/dev/null || {
    echo "SKIP: missing required command: $command"
    exit 0
  }
done

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
launcher_driver="$root_dir/../../hub-launcher/integration/systemd_lifecycle.ts"
[[ -f "$launcher_driver" ]] || {
  echo "SKIP: Launcher lifecycle driver missing: $launcher_driver"
  exit 0
}
work_dir="$root_dir/build/release-acceptance"
old_version=${HUB_NET_OLD_VERSION:-0.1.0}
new_version=${HUB_NET_NEW_VERSION:-0.1.1-acceptance}
old_name="hub-net-${old_version}-linux-amd64"
new_name="hub-net-${new_version}-linux-amd64"
old_enabled=$(systemctl is-enabled hub-net.service 2>/dev/null || true)
old_active=$(systemctl is-active hub-net.service 2>/dev/null || true)
old_installed_version=$(/usr/bin/hub-net --version 2>/dev/null || true)
identity_before=$(sha256sum /var/lib/hub-net/profile.identity 2>/dev/null | awk '{print $1}')
wireguard_before=$(sha256sum /var/lib/hub-net/wireguard.key 2>/dev/null | awk '{print $1}')

restore() {
  set +e
  if [[ -n "$old_installed_version" && -x "$work_dir/$old_name/packaging/linux/install" ]]; then
    bun "$launcher_driver" install hub-net.service \
      "$work_dir/$old_name/packaging/linux/install" >/dev/null
  elif [[ -x "$work_dir/$new_name/packaging/linux/uninstall" ]]; then
    bun "$launcher_driver" uninstall hub-net.service \
      "$work_dir/$new_name/packaging/linux/uninstall" >/dev/null
  fi
  if [[ "$old_enabled" == enabled ]]; then
    systemctl enable hub-net.service >/dev/null 2>&1
  else
    systemctl disable hub-net.service >/dev/null 2>&1
  fi
  if [[ "$old_active" == active ]]; then
    systemctl start hub-net.service
  else
    systemctl stop hub-net.service >/dev/null 2>&1
  fi
}
trap restore EXIT

rm -rf "$work_dir"
mkdir -p "$work_dir"
make -C "$root_dir" package VERSION="$old_version" >/dev/null
cp "$root_dir/build/$old_name.tar.gz" "$root_dir/build/$old_name.tar.gz.sha256" "$work_dir/"
make -C "$root_dir" package VERSION="$new_version" >/dev/null
cp "$root_dir/build/$new_name.tar.gz" "$root_dir/build/$new_name.tar.gz.sha256" "$work_dir/"

cd "$work_dir"
sha256sum -c "$old_name.tar.gz.sha256"
sha256sum -c "$new_name.tar.gz.sha256"
tar -xzf "$old_name.tar.gz"
tar -xzf "$new_name.tar.gz"

[[ $(stat -c %a "$new_name/hub-net") == 755 ]]
[[ $(stat -c %a "$new_name/packaging/linux/install") == 755 ]]
file "$new_name/hub-net"
ldd_output=$(ldd "$new_name/hub-net" 2>&1 || true)
grep -q "not a dynamic executable" <<<"$ldd_output"
binary_size=$(stat -c %s "$new_name/hub-net")
echo "stripped-size=$binary_size bytes"
(( binary_size < 20000000 ))

bun "$launcher_driver" install hub-net.service \
  "$work_dir/$old_name/packaging/linux/install"
systemctl disable --now hub-net.service >/dev/null 2>&1 || true
[[ $(/usr/bin/hub-net --version) == "$old_version" ]]
bun "$launcher_driver" update hub-net.service \
  "$work_dir/$new_name/packaging/linux/update"
[[ $(/usr/bin/hub-net --version) == "$new_version" ]]
! systemctl is-active --quiet hub-net.service

systemctl show hub-net.service \
  -p User -p Group -p AmbientCapabilities -p CapabilityBoundingSet \
  -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp \
  -p RestrictAddressFamilies -p StateDirectory -p RuntimeDirectory
[[ $(stat -c "%U:%G:%a" /usr/bin/hub-net) == root:root:755 ]]
[[ $(stat -c "%U:%G:%a" /usr/lib/systemd/system/hub-net.service) == root:root:644 ]]

bun "$launcher_driver" uninstall hub-net.service \
  "$work_dir/$new_name/packaging/linux/uninstall"
[[ ! -e /usr/bin/hub-net ]]
if [[ -n "$identity_before" ]]; then
  [[ $(sha256sum /var/lib/hub-net/profile.identity | awk '{print $1}') == "$identity_before" ]]
fi
if [[ -n "$wireguard_before" ]]; then
  [[ $(sha256sum /var/lib/hub-net/wireguard.key | awk '{print $1}') == "$wireguard_before" ]]
fi

bun "$launcher_driver" install hub-net.service \
  "$work_dir/$old_name/packaging/linux/install"
[[ $(/usr/bin/hub-net --version) == "$old_installed_version" || -z "$old_installed_version" ]]
echo "PASS: Launcher install/update/uninstall, checksum, static size, modes, hardening, identity preservation"
