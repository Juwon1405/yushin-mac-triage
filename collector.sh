#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# macOS DFIR Artifact Collector v2.0
# ============================================================================
# Modular forensic artifact collector for macOS incident response.
# Each collection domain is isolated into its own function for easy
# maintenance, selective execution, and future extension.
#
# Usage:
#   ./collector.sh                        # Full collection (all modules)
#   ./collector.sh --quick                 # Reduced log window / line limits
#   ./collector.sh --modules system,network,supply_chain   # Selected modules only
#   ./collector.sh --list-modules          # Show available modules
#
# Environment:
#   COLLECTOR_QUICK=1   Same as --quick
# ============================================================================

# ── Global Setup ────────────────────────────────────────────────────────────

HOST_RAW="$(scutil --get ComputerName 2>/dev/null || hostname -s || hostname)"
HOST="${HOST_RAW// /_}"
TS="$(date '+%Y%m%d_%H%M')"
BASE="${HOST}_${TS}"
WORK="${TMPDIR:-/tmp}/${BASE}_collect"
OUT="$PWD/${BASE}.zip"
QUICK="${COLLECTOR_QUICK:-0}"

# ── Argument Parsing ────────────────────────────────────────────────────────

SELECTED_MODULES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      QUICK=1
      shift
      ;;
    --modules)
      SELECTED_MODULES="$2"
      shift 2
      ;;
    --list-modules)
      cat <<'LIST'
Available modules:
  system            OS info, Gatekeeper, SIP, FileVault, kext, XProtect
  persistence       LaunchAgents/Daemons, crontab, login items, processes
  accounts          Local users, login history, shell history
  network           Interfaces, connections, DNS, remote access logs
  remote_kvm        USB/Thunderbolt enumeration, KVM keyword detection
  security_agents   CrowdStrike, Tanium, JAMF presence and logs
  browser           Chrome, Edge, Firefox, Safari history DBs (+WAL/SHM)
  logs              Unified log, auth/remote log, system.log
  timeline          Installed apps, pkgutil, InstallHistory
  supply_chain      Python/Node.js supply chain attack IOC detection
LIST
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# ── Log Window / Limit Configuration ───────────────────────────────────────

if [[ "$QUICK" == "1" ]]; then
  LOG_WINDOW_SHORT="1h"
  LOG_WINDOW_LONG="6h"
  LOG_LIMIT_MAIN="30000"
  LOG_LIMIT_FILTERED="20000"
else
  LOG_WINDOW_SHORT="6h"
  LOG_WINDOW_LONG="24h"
  LOG_LIMIT_MAIN="150000"
  LOG_LIMIT_FILTERED="100000"
fi

# ── Module Selection Logic ─────────────────────────────────────────────────

ALL_MODULES="system persistence accounts network remote_kvm security_agents browser logs timeline supply_chain"

if [[ -n "$SELECTED_MODULES" ]]; then
  IFS=',' read -ra ENABLED_MODULES <<< "$SELECTED_MODULES"
else
  IFS=' ' read -ra ENABLED_MODULES <<< "$ALL_MODULES"
fi

module_enabled() {
  local mod="$1"
  for m in "${ENABLED_MODULES[@]}"; do
    [[ "$m" == "$mod" ]] && return 0
  done
  return 1
}

# ── Directory Scaffolding ──────────────────────────────────────────────────

mkdir -p "$WORK"/metadata

for mod in "${ENABLED_MODULES[@]}"; do
  mkdir -p "$WORK/$mod"
done

# ── Progress Tracking ─────────────────────────────────────────────────────

STEP_TOTAL=0
STEP_DONE=0

add_steps() {
  STEP_TOTAL=$((STEP_TOTAL + $1))
}

progress_step() {
  local action="$1"
  STEP_DONE=$((STEP_DONE + 1))
  if (( STEP_DONE > STEP_TOTAL )); then
    STEP_TOTAL=$STEP_DONE
  fi
  local pct=$(( STEP_DONE * 100 / STEP_TOTAL ))
  printf '[%3d%%] (%d/%d) %s\n' "$pct" "$STEP_DONE" "$STEP_TOTAL" "$action"
}

# ── Core Helpers ───────────────────────────────────────────────────────────

capture() {
  local cmd="$1"
  local out="$2"
  local timeout_sec="${3:-120}"
  local desc="${4:-$(basename "$out")}"

  progress_step "Collecting: $desc"

  (
    bash -lc "$cmd" > "$out" 2>&1
  ) &
  local pid=$!
  local elapsed=0

  while kill -0 "$pid" 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed + 1))
    if (( elapsed >= timeout_sec )); then
      {
        echo ""
        echo "[timeout] command exceeded ${timeout_sec}s and was terminated"
        echo "[timeout] $cmd"
      } >> "$out"
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
  done

  wait "$pid" 2>/dev/null || true
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  local desc="${3:-$(basename "$dst")}"
  progress_step "Copying: $desc"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" 2>/dev/null || true
  else
    echo "[skip] not found: $src" > "$dst.skip" 2>/dev/null || true
  fi
}

copy_with_wal() {
  local src="$1"
  local dst="$2"
  local desc="${3:-$(basename "$dst")}"
  progress_step "Copying (with WAL/SHM): $desc"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" 2>/dev/null || true
    [[ -f "${src}-wal" ]] && cp "${src}-wal" "${dst}-wal" 2>/dev/null || true
    [[ -f "${src}-shm" ]] && cp "${src}-shm" "${dst}-shm" 2>/dev/null || true
  else
    echo "[skip] not found: $src" > "$dst.skip" 2>/dev/null || true
  fi
}

sanitize_name() {
  local raw="$1"
  raw="${raw// /_}"
  raw="${raw//\//_}"
  raw="${raw//:/_}"
  printf '%s' "$raw"
}

count_files() {
  local dir="$1"
  local name="$2"
  if [[ -d "$dir" ]]; then
    find "$dir" -type f -name "$name" 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

# ============================================================================
# MODULE: system
# ============================================================================
module_system() {
  add_steps 17
  capture "date"                              "$WORK/system/date.txt"
  capture "whoami"                            "$WORK/system/whoami.txt"
  capture "id"                                "$WORK/system/id.txt"
  capture "uname -a"                          "$WORK/system/uname.txt"
  capture "sw_vers"                           "$WORK/system/sw_vers.txt"
  capture "uptime"                            "$WORK/system/uptime.txt"
  capture "sysctl kern.boottime"              "$WORK/system/boot_time.txt"
  capture "system_profiler SPHardwareDataType SPSoftwareDataType" \
          "$WORK/system/system_profiler_hw_sw.txt" 240
  capture "spctl --status"                    "$WORK/system/gatekeeper_status.txt"
  capture "csrutil status"                    "$WORK/system/sip_status.txt"
  capture "fdesetup status"                   "$WORK/system/filevault_status.txt"
  capture "kextstat"                          "$WORK/system/kextstat.txt"
  capture "kmutil showloaded"                 "$WORK/system/kmutil_showloaded.txt"
  capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"xprotect\" OR eventMessage CONTAINS[c] \"malware\" OR eventMessage CONTAINS[c] \"quarantine\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" \
          "$WORK/system/xprotect_quarantine.log" 240
  capture "sqlite3 '$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2' \
          'select datetime(LSQuarantineTimeStamp+978307200,\"unixepoch\"), LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 3000;'" \
          "$WORK/system/quarantine_events.txt"
  # Gatekeeper assessment of common Python interpreters
  capture "for py in \$(which -a python3 python 2>/dev/null); do echo \"--- \$py ---\"; codesign -dvvv \"\$py\" 2>&1; done" \
          "$WORK/system/python_codesign.txt" 60
  capture "profiles status -type enrollment"  "$WORK/system/mdm_enrollment_status.txt"
}

# ============================================================================
# MODULE: persistence
# ============================================================================
module_persistence() {
  add_steps 12
  capture "ps aux"                            "$WORK/persistence/ps_aux.txt"
  capture "launchctl list"                    "$WORK/persistence/launchctl_list.txt"
  capture "find '$HOME/Library/LaunchAgents' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" \
          "$WORK/persistence/user_launchagents.txt"
  capture "find '/Library/LaunchAgents' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" \
          "$WORK/persistence/system_launchagents.txt"
  capture "find '/Library/LaunchDaemons' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" \
          "$WORK/persistence/system_launchdaemons.txt"
  capture "crontab -l"                        "$WORK/persistence/user_crontab.txt"
  capture "osascript -e 'tell application \"System Events\" to get the name of every login item'" \
          "$WORK/persistence/login_items.txt" 30
  capture "ls -la '$HOME/Library/LaunchAgents'" \
          "$WORK/persistence/user_launchagents_ls.txt"
  capture "ls -la '/Library/LaunchAgents'"    "$WORK/persistence/system_launchagents_ls.txt"
  capture "ls -la '/Library/LaunchDaemons'"   "$WORK/persistence/system_launchdaemons_ls.txt"
  capture "defaults read com.apple.loginwindow AutoLaunchedApplicationDictionary" \
          "$WORK/persistence/auto_launched_apps.txt"
  # sysmon-style persistence (litellm / generic supply chain backdoor)
  capture "find '$HOME/.config' -type f \\( -name '*.py' -o -name '*.service' -o -name '*.plist' \\) 2>/dev/null | head -200" \
          "$WORK/persistence/dotconfig_scripts.txt"
}

# ============================================================================
# MODULE: accounts
# ============================================================================
module_accounts() {
  add_steps 4
  capture "cat '$HOME/.zsh_history'"          "$WORK/accounts/zsh_history.txt"
  capture "cat '$HOME/.bash_history'"         "$WORK/accounts/bash_history.txt"
  capture "last -100"                         "$WORK/accounts/last_logins.txt"
  capture "dscl . -list /Users"               "$WORK/accounts/local_users.txt"
}

# ============================================================================
# MODULE: network
# ============================================================================
module_network() {
  add_steps 11
  capture "ifconfig -a"                       "$WORK/network/ifconfig.txt"
  capture "netstat -anv"                      "$WORK/network/netstat_anv.txt"
  capture "lsof -nP -i"                       "$WORK/network/lsof_network.txt"
  capture "route -n get default"              "$WORK/network/route_default.txt"
  capture "arp -a"                            "$WORK/network/arp.txt"
  capture "networksetup -listallhardwareports" "$WORK/network/hardware_ports.txt"
  capture "networksetup -listallnetworkservices" "$WORK/network/network_services.txt"
  capture "scutil --dns"                      "$WORK/network/dns_config.txt"
  capture "cat /etc/hosts"                    "$WORK/network/etc_hosts.txt"
  capture "cat /etc/resolv.conf"              "$WORK/network/resolv.conf.txt"
  capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"ssh\" OR eventMessage CONTAINS[c] \"screen sharing\" OR eventMessage CONTAINS[c] \"vnc\" OR eventMessage CONTAINS[c] \"ard\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" \
          "$WORK/network/remote_access_logs.txt" 240
}

# ============================================================================
# MODULE: remote_kvm
# ============================================================================
module_remote_kvm() {
  add_steps 7
  capture "system_profiler SPUSBDataType"            "$WORK/remote_kvm/usb_devices.txt" 240
  capture "system_profiler SPThunderboltDataType"    "$WORK/remote_kvm/thunderbolt_devices.txt" 180
  capture "system_profiler SPEthernetDataType"       "$WORK/remote_kvm/ethernet_devices.txt" 180
  capture "system_profiler SPNetworkDataType"        "$WORK/remote_kvm/network_devices.txt" 180
  capture "system_profiler SPDisplaysDataType"       "$WORK/remote_kvm/displays.txt" 180
  capture "pmset -g"                                 "$WORK/remote_kvm/pmset.txt"
  capture "grep -iE 'kvm|pikvm|ipmi|idrac|ilo|bmc|remote console|virtual media' \
          '$WORK/remote_kvm/usb_devices.txt' \
          '$WORK/remote_kvm/thunderbolt_devices.txt' \
          '$WORK/remote_kvm/ethernet_devices.txt' \
          '$WORK/remote_kvm/network_devices.txt' 2>/dev/null || echo '[none]'" \
          "$WORK/remote_kvm/kvm_keyword_hits.txt"
}

# ============================================================================
# MODULE: security_agents
# ============================================================================
module_security_agents() {
  add_steps 18
  capture "ls -la '/Applications' | grep -iE 'falcon|crowdstrike|tanium|jamf'" \
          "$WORK/security_agents/app_presence.txt"
  capture "ps aux | grep -iE 'falcon|crowdstrike|tanium|jamf' | grep -v grep" \
          "$WORK/security_agents/process_presence.txt"
  capture "ls -la '/Library/LaunchDaemons' | grep -iE 'falcon|crowdstrike|tanium|jamf'" \
          "$WORK/security_agents/launchdaemons_presence.txt"
  capture "ls -la '/Library/LaunchAgents' | grep -iE 'falcon|crowdstrike|tanium|jamf'" \
          "$WORK/security_agents/launchagents_presence.txt"
  capture "systemextensionsctl list 2>/dev/null | grep -iE 'falcon|crowdstrike|tanium|jamf'" \
          "$WORK/security_agents/systemextensions_presence.txt"
  capture "profiles status -type enrollment"         "$WORK/security_agents/mdm_enrollment_status.txt"
  capture "profiles show -type enrollment"           "$WORK/security_agents/mdm_enrollment_detail.txt"
  capture "jamf checkJSSConnection"                  "$WORK/security_agents/jamf_checkJSSConnection.txt"
  capture "jamf version"                             "$WORK/security_agents/jamf_version.txt"
  capture "grep -iE 'falcon|crowdstrike|tanium|jamf' /var/log/system.log 2>/dev/null | tail -500" \
          "$WORK/security_agents/system_log_agent_hits.txt"
  copy_if_exists "/usr/local/bin/jamf"                                       "$WORK/security_agents/jamf_binary"
  copy_if_exists "/Library/LaunchDaemons/com.jamf.management.daemon.plist"   "$WORK/security_agents/com.jamf.management.daemon.plist"
  copy_if_exists "/Library/Preferences/com.jamfsoftware.jamf.plist"          "$WORK/security_agents/com.jamfsoftware.jamf.plist"
  copy_if_exists "/Library/LaunchDaemons/com.crowdstrike.falcond.plist"      "$WORK/security_agents/com.crowdstrike.falcond.plist"
  copy_if_exists "/Library/CS/falcond"                                       "$WORK/security_agents/falcond_binary"
  copy_if_exists "/Library/Logs/Falcon/falconctl.log"                        "$WORK/security_agents/falconctl.log"
  copy_if_exists "/Library/Logs/Falcon/falcond.log"                          "$WORK/security_agents/falcond.log"
  copy_if_exists "/Library/Tanium/TaniumClient/Logs/TaniumClient.log"        "$WORK/security_agents/TaniumClient.log"
}

# ============================================================================
# MODULE: browser
# ============================================================================
module_browser() {
  # Pre-count browser DBs for accurate progress
  local bc=0
  bc=$((bc + $(count_files "$HOME/Library/Application Support/Google/Chrome" "History")))
  bc=$((bc + $(count_files "$HOME/Library/Application Support/Microsoft Edge" "History")))
  bc=$((bc + $(count_files "$HOME/Library/Application Support/Firefox/Profiles" "places.sqlite")))
  bc=$((bc + 1))  # Safari
  add_steps "$bc"

  # Chrome
  if [[ -d "$HOME/Library/Application Support/Google/Chrome" ]]; then
    while IFS= read -r p; do
      local rel="${p#$HOME/Library/Application Support/Google/Chrome/}"
      local rel_clean="$(sanitize_name "$rel")"
      copy_with_wal "$p" "$WORK/browser/chrome_${rel_clean}.db" "chrome_${rel_clean}"
    done < <(find "$HOME/Library/Application Support/Google/Chrome" -type f -name 'History' 2>/dev/null)
  fi

  # Edge
  if [[ -d "$HOME/Library/Application Support/Microsoft Edge" ]]; then
    while IFS= read -r p; do
      local rel="${p#$HOME/Library/Application Support/Microsoft Edge/}"
      local rel_clean="$(sanitize_name "$rel")"
      copy_with_wal "$p" "$WORK/browser/edge_${rel_clean}.db" "edge_${rel_clean}"
    done < <(find "$HOME/Library/Application Support/Microsoft Edge" -type f -name 'History' 2>/dev/null)
  fi

  # Firefox
  if [[ -d "$HOME/Library/Application Support/Firefox/Profiles" ]]; then
    while IFS= read -r p; do
      local rel="${p#$HOME/Library/Application Support/Firefox/Profiles/}"
      local rel_clean="$(sanitize_name "$rel")"
      copy_with_wal "$p" "$WORK/browser/firefox_${rel_clean}.db" "firefox_${rel_clean}"
    done < <(find "$HOME/Library/Application Support/Firefox/Profiles" -type f -name 'places.sqlite' 2>/dev/null)
  fi

  # Safari
  copy_with_wal "$HOME/Library/Safari/History.db" "$WORK/browser/safari_History.db" "safari_History"
}

# ============================================================================
# MODULE: logs
# ============================================================================
module_logs() {
  add_steps 5
  capture "log show --last ${LOG_WINDOW_SHORT} --style syslog | head -n ${LOG_LIMIT_MAIN}" \
          "$WORK/logs/unified_last.log" 300
  capture "log show --last ${LOG_WINDOW_SHORT} --predicate 'eventMessage CONTAINS[c] \"ssh\" OR eventMessage CONTAINS[c] \"auth\" OR eventMessage CONTAINS[c] \"screen sharing\" OR eventMessage CONTAINS[c] \"remote\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" \
          "$WORK/logs/auth_remote_last.log" 240
  capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"tcc\" OR eventMessage CONTAINS[c] \"privacy\" OR eventMessage CONTAINS[c] \"mdm\" OR eventMessage CONTAINS[c] \"jamf\" OR eventMessage CONTAINS[c] \"tanium\" OR eventMessage CONTAINS[c] \"falcon\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" \
          "$WORK/logs/security_controls_last.log" 240
  copy_if_exists "/var/log/system.log"   "$WORK/logs/system.log"
  copy_if_exists "/var/log/jamf.log"     "$WORK/logs/jamf.log"
}

# ============================================================================
# MODULE: timeline
# ============================================================================
module_timeline() {
  add_steps 4
  capture "system_profiler SPApplicationsDataType -detailLevel mini" \
          "$WORK/timeline/installed_apps.txt" 300
  capture "pkgutil --pkgs"                   "$WORK/timeline/pkgutil_pkgs.txt"
  copy_if_exists "/Library/Receipts/InstallHistory.plist" "$WORK/timeline/InstallHistory.plist"
  copy_if_exists "/var/log/install.log"      "$WORK/timeline/install.log"
}

# ============================================================================
# MODULE: supply_chain  — Python / Node.js supply chain attack detection
# ============================================================================
# Covers IOCs for litellm PyPI attack (2026-03-24) and generic patterns:
#   - Malicious .pth files in site-packages
#   - Backdoor persistence in ~/.config/sysmon/
#   - C2 domain DNS resolution (models.litellm.cloud, etc.)
#   - Package manager cache and install state
#   - Credential file access timestamps (exfil detection)
#   - Node.js preinstall/postinstall hook abuse
# ============================================================================
module_supply_chain() {
  add_steps 25

  local D="$WORK/supply_chain"

  # ── 1. Known malicious .pth files (litellm_init.pth and generic) ────────
  capture "find / -maxdepth 8 -name 'litellm_init.pth' -type f 2>/dev/null" \
          "$D/pth_litellm_init.txt" 120 "PTH: litellm_init.pth scan"

  capture "find / -maxdepth 8 -path '*/site-packages/*.pth' -type f 2>/dev/null | while read -r f; do echo \"=== \$f ===\"; head -5 \"\$f\"; echo; done" \
          "$D/pth_all_site_packages.txt" 180 "PTH: all .pth in site-packages"

  # ── 2. Python package audit ─────────────────────────────────────────────
  capture "for py in \$(which -a python3 python 2>/dev/null | sort -u); do echo \"--- \$py ---\"; \"\$py\" -m pip list --format=json 2>/dev/null || \"\$py\" -m pip list 2>/dev/null || echo '[pip unavailable]'; echo; done" \
          "$D/pip_list_all.txt" 120 "pip list (all interpreters)"

  capture "for py in \$(which -a python3 python 2>/dev/null | sort -u); do echo \"--- \$py ---\"; \"\$py\" -m pip show litellm 2>/dev/null || echo '[not installed]'; echo; done" \
          "$D/pip_show_litellm.txt" 60 "pip show litellm"

  capture "find '$HOME' /tmp -maxdepth 6 -path '*/site-packages/litellm*' -type d 2>/dev/null" \
          "$D/litellm_site_packages_dirs.txt" 120 "litellm dirs in site-packages"

  # ── 3. Package manager caches (pip / uv / pipx) ────────────────────────
  capture "find '$HOME/.cache/uv' -name 'litellm*' -o -name '*.pth' 2>/dev/null | head -200" \
          "$D/uv_cache_litellm.txt" 60 "uv cache: litellm artifacts"

  capture "find '$HOME/.cache/pip' '$HOME/Library/Caches/pip' -name 'litellm*' 2>/dev/null | head -200" \
          "$D/pip_cache_litellm.txt" 60 "pip cache: litellm artifacts"

  capture "find '$HOME/.local/pipx' -name 'litellm*' 2>/dev/null | head -200" \
          "$D/pipx_litellm.txt" 60 "pipx: litellm check"

  # ── 4. Virtual environments scan ────────────────────────────────────────
  capture "find '$HOME' -maxdepth 5 -type d -name 'site-packages' 2>/dev/null | while read -r sp; do
    pth=\$(find \"\$sp\" -maxdepth 1 -name '*.pth' -type f 2>/dev/null)
    lit=\$(find \"\$sp\" -maxdepth 1 -type d -name 'litellm' 2>/dev/null)
    if [[ -n \"\$pth\" || -n \"\$lit\" ]]; then
      echo \"=== \$sp ===\"
      [[ -n \"\$lit\" ]] && echo \"  [!] litellm installed\"
      [[ -n \"\$pth\" ]] && echo \"  .pth files:\" && echo \"\$pth\" | sed 's/^/    /'
    fi
  done" "$D/venv_scan.txt" 180 "Virtual environment litellm/.pth scan"

  # ── 5. Backdoor persistence (sysmon pattern) ───────────────────────────
  capture "ls -laR '$HOME/.config/sysmon/' 2>/dev/null || echo '[not found]'" \
          "$D/sysmon_backdoor_ls.txt" 10 "Backdoor: ~/.config/sysmon/"

  capture "cat '$HOME/.config/sysmon/sysmon.py' 2>/dev/null || echo '[not found]'" \
          "$D/sysmon_backdoor_content.txt" 10 "Backdoor: sysmon.py content"

  capture "find '$HOME/.config/systemd' -type f 2>/dev/null || echo '[not found — expected on macOS]'" \
          "$D/systemd_user_services.txt" 10 "Backdoor: systemd user services"

  capture "find '$HOME/Library/LaunchAgents' -type f -name '*.plist' -newer /var/log/system.log 2>/dev/null | head -50" \
          "$D/recent_launchagents.txt" 30 "Recent LaunchAgents (post-attack window)"

  # ── 6. C2 domain / network IOC ─────────────────────────────────────────
  capture "log show --last ${LOG_WINDOW_LONG} --predicate 'process == \"mDNSResponder\" AND (eventMessage CONTAINS \"litellm.cloud\" OR eventMessage CONTAINS \"litellm\")' --style syslog | head -n 5000" \
          "$D/dns_litellm_cloud.txt" 180 "DNS: litellm.cloud resolution"

  capture "grep -rn 'models.litellm.cloud\|litellm.cloud' '$HOME/.zsh_history' '$HOME/.bash_history' '$HOME/.python_history' 2>/dev/null || echo '[no hits]'" \
          "$D/history_c2_grep.txt" 30 "Shell history: C2 domain grep"

  capture "lsof -nP -i | grep -iE 'litellm|sysmon' || echo '[no active connections]'" \
          "$D/lsof_c2_check.txt" 30 "lsof: active C2 connections"

  capture "netstat -anv | grep -E '443|8443|4443' | head -100" \
          "$D/netstat_tls_connections.txt" 30 "netstat: outbound TLS connections"

  # ── 7. Credential file access timestamps (exfiltration detection) ──────
  capture "for f in '$HOME/.ssh/id_rsa' '$HOME/.ssh/id_ed25519' '$HOME/.ssh/config' \
           '$HOME/.aws/credentials' '$HOME/.aws/config' \
           '$HOME/.kube/config' '$HOME/.gitconfig' \
           '$HOME/.gcloud/application_default_credentials.json' \
           '$HOME/.azure/accessTokens.json' '$HOME/.azure/azureProfile.json'; do
    [[ -f \"\$f\" ]] && stat -f '%Sa  %Sm  %N' \"\$f\" 2>/dev/null
  done" "$D/credential_file_timestamps.txt" 30 "Credential file atime/mtime"

  capture "find '$HOME' -maxdepth 3 -name '.env' -type f -exec stat -f '%Sa  %Sm  %N' {} \\; 2>/dev/null | head -100" \
          "$D/dotenv_timestamps.txt" 60 ".env file access timestamps"

  # ── 8. Kubernetes artifacts (if present on macOS dev workstation) ──────
  capture "if [[ -f '$HOME/.kube/config' ]]; then
    echo '[!] kubeconfig exists — checking for service account tokens'
    find /var/run/secrets /run/secrets -type f 2>/dev/null || echo '[no k8s SA tokens]'
    kubectl get pods -n kube-system 2>/dev/null | grep -i 'node-setup' || echo '[no suspicious pods]'
  else
    echo '[skip] no kubeconfig found'
  fi" "$D/k8s_check.txt" 30 "Kubernetes lateral movement check"

  # ── 9. Node.js supply chain (generic coverage) ─────────────────────────
  capture "find '$HOME' /tmp -maxdepth 5 -name 'package.json' -type f 2>/dev/null | while read -r pj; do
    if grep -qE 'preinstall|postinstall' \"\$pj\" 2>/dev/null; then
      echo \"=== \$pj ===\"
      grep -A2 -E 'preinstall|postinstall' \"\$pj\"
      echo
    fi
  done | head -500" "$D/npm_prepostinstall_hooks.txt" 120 "npm: pre/post install hook scan"

  # ── 10. Anomalous Python process detection ─────────────────────────────
  capture "ps aux | grep -i python | grep -v grep | awk '{print \$2, \$3, \$4, \$11, \$12, \$13}'" \
          "$D/python_processes.txt" 15 "Running Python processes"

  capture "ps aux | awk '/[Pp]ython/{c++} END{print \"python_process_count=\" c}'" \
          "$D/python_process_count.txt" 10 "Python process count (fork bomb indicator)"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

echo "============================================================================"
echo " macOS DFIR Artifact Collector v2.0"
echo " Host     : $HOST_RAW"
echo " Timestamp: $TS"
echo " Mode     : $([ "$QUICK" = "1" ] && echo "QUICK" || echo "FULL")"
echo " Modules  : ${ENABLED_MODULES[*]}"
echo " Output   : $OUT"
echo "============================================================================"
echo ""

# Pre-calculate total steps: metadata(2) + packaging(2)
add_steps 4

# Execute selected modules
module_enabled "system"          && module_system
module_enabled "persistence"     && module_persistence
module_enabled "accounts"        && module_accounts
module_enabled "network"         && module_network
module_enabled "remote_kvm"      && module_remote_kvm
module_enabled "security_agents" && module_security_agents
module_enabled "browser"         && module_browser
module_enabled "logs"            && module_logs
module_enabled "timeline"        && module_timeline
module_enabled "supply_chain"    && module_supply_chain

# ── Metadata & Integrity ──────────────────────────────────────────────────

progress_step "Writing collection metadata"
cat > "$WORK/metadata/collection_meta.txt" << META
collector_version=2.0
collector_name=macOS DFIR Artifact Collector
host=$HOST_RAW
timestamp=$TS
mode=$([ "$QUICK" = "1" ] && echo "quick" || echo "full")
modules=${ENABLED_MODULES[*]}
output_zip=$OUT
META

capture "find '$WORK' -type f -print0 | xargs -0 shasum -a 256" \
        "$WORK/metadata/hashes_sha256.txt" 120 "SHA-256 hash manifest"

# ── Package ────────────────────────────────────────────────────────────────

progress_step "Packaging collected artifacts into ZIP"
if command -v ditto >/dev/null 2>&1; then
  PARENT="$(dirname "$WORK")"
  NAME="$(basename "$WORK")"
  (cd "$PARENT" && ditto -c -k --sequesterRsrc --keepParent "$NAME" "$OUT")
else
  (cd "$WORK" && /usr/bin/zip -r "$OUT" . >/dev/null)
fi

progress_step "Cleaning temporary working directory"
rm -rf "$WORK"

echo ""
echo "============================================================================"
echo " [+] Collection complete: $OUT"
echo "============================================================================"
