# yushin-mac-artifact-collector

> **macOS DFIR Artifact Collector** — a single-file, zero-dependency artifact collection script for macOS incident response.

[![Shell](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![macOS](https://img.shields.io/badge/macOS-10.15%2B-000000?logo=apple&logoColor=white)](https://support.apple.com/macos)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

A modular, evidence-grade artifact collector built for DFIR analysts who need rapid forensic data from macOS endpoints — no agent installation, no Homebrew, no Python. Just `bash` + macOS built-in utilities.

> **What it is:** an artifact *collector* (not an analyzer). It produces a hashed ZIP of forensic artifacts that you then triage, parse, or feed into your analysis pipeline of choice. For a companion analysis platform, see [yushin-mac-forensics-platform](https://github.com/Juwon1405/yushin-mac-forensics-platform).

---

## ✨ Highlights

- **Single file, zero deps.** Drop `collector.sh` onto any macOS box (10.15+) and run.
- **10 independent modules.** Run all, run one, run a comma-separated subset.
- **Evidence-grade.** SHA-256 manifest of every collected artifact for chain-of-custody.
- **Timeout-protected.** Every command is wrapped — hung commands are killed and tagged `[timeout]`, never blocking the whole run.
- **Supply-chain attack module.** Built-in IOC sweep for the [litellm PyPI supply chain attack (2026-03)](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/) and generic `.pth` / cache-poisoning patterns.
- **Browser DBs with WAL/SHM.** Chrome / Edge / Firefox / Safari history copied with sidecar files to preserve uncommitted transactions.

---

## 🚀 Quick Start

```bash
# Full collection (all modules) — sudo recommended for full coverage
sudo ./collector.sh

# Quick mode (reduced log window, faster collection)
sudo ./collector.sh --quick

# Run specific modules only
./collector.sh --modules supply_chain,network,persistence

# List available modules
./collector.sh --list-modules
```

**Output:** `{hostname}_{YYYYMMDD_HHMM}.zip` in the current working directory.

---

## 📋 Requirements

| Item | Detail |
|------|--------|
| OS | macOS 10.15 (Catalina) or later |
| Shell | `/bin/bash` (pre-installed on all macOS) |
| Privileges | Runs without `sudo`, but **`sudo` recommended** for full `/Library/`, `/var/log/`, and Unified Log access |
| Dependencies | None — uses only built-in macOS utilities (`system_profiler`, `log`, `sqlite3`, `lsof`, `ditto`, etc.) |
| Disk | ~50–300 MB temporary space in `/tmp/` during collection (cleaned automatically) |

---

## 🧩 Modules

The collector is organized into **10 independent modules**. Each can be invoked individually or in any combination via `--modules`.

### Core Forensic Modules

#### `system`
OS-level configuration and security posture.
- macOS version, hardware profile, kernel info, uptime, boot time
- Gatekeeper, SIP (System Integrity Protection), FileVault status
- Loaded kernel extensions (`kextstat`, `kmutil`)
- XProtect / quarantine event history (SQLite dump)
- MDM enrollment status
- Python interpreter code signature verification

#### `persistence`
Mechanisms that survive reboot or login.
- Running processes (`ps aux`)
- LaunchAgents (user + system), LaunchDaemons
- `launchctl list` output
- Crontab entries, login items
- `~/.config/` script enumeration (catches supply-chain backdoor patterns like `sysmon.py`)

#### `accounts`
User identity and activity history.
- Local user list (`dscl`)
- Login history (`last -100`)
- Full `zsh_history` and `bash_history`

#### `network`
Network configuration and active connections.
- Interface config, routing table, ARP cache
- Active connections (`netstat -anv`, `lsof -nP -i`)
- DNS configuration (`scutil --dns`, `/etc/hosts`, `/etc/resolv.conf`)
- SSH / VNC / ARD / Screen Sharing log entries from Unified Log

#### `remote_kvm`
USB/Thunderbolt device enumeration for IP-KVM detection (e.g., PiKVM, IPMI, iDRAC).
- `system_profiler` for USB, Thunderbolt, Ethernet, Network, Displays
- Keyword grep for KVM/BMC/IPMI indicators across device inventories
- Power management settings (`pmset`)

#### `security_agents`
Endpoint security tooling health check.
- CrowdStrike Falcon: process, daemon plist, binary, logs
- Tanium: client binary, plist, logs
- JAMF: binary, JSS connection, version, plist
- System extension status, MDM enrollment detail

#### `browser`
Browser history database collection with WAL/SHM integrity.
- Google Chrome (all profiles)
- Microsoft Edge (all profiles)
- Mozilla Firefox (all profiles)
- Safari
- Copies `-wal` and `-shm` sidecar files to preserve uncommitted transactions

#### `logs`
macOS Unified Log and legacy log collection.
- Unified Log: last 6h (full mode) or 1h (quick mode)
- Filtered Unified Log: auth, remote access, TCC, privacy, security agent events
- `/var/log/system.log`, `/var/log/jamf.log`

#### `timeline`
Software installation timeline.
- Installed applications (`system_profiler SPApplicationsDataType`)
- Registered packages (`pkgutil --pkgs`)
- `/Library/Receipts/InstallHistory.plist`
- `/var/log/install.log`

### Supply Chain Attack Module

#### `supply_chain`
Python and Node.js supply chain attack IOC detection. Built in response to the [litellm PyPI supply chain attack (2026-03-24)](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/) but designed for **generic supply chain attack triage**.

| Check | What It Detects |
|-------|-----------------|
| **Malicious `.pth` files** | `litellm_init.pth` full-disk scan + content dump of all `.pth` files in `site-packages` |
| **Package audit** | `pip list` / `pip show litellm` across all Python interpreters |
| **Cache poisoning** | Scans `uv`, `pip`, and `pipx` caches for malicious artifacts |
| **Virtual environment scan** | Finds all `site-packages` dirs under `~/`, checks for litellm + `.pth` files |
| **Backdoor persistence** | `~/.config/sysmon/sysmon.py` (litellm backdoor pattern) |
| **C2 communication** | DNS resolution logs for `litellm.cloud`, `lsof` for active C2 connections |
| **Credential exfiltration** | Access timestamps on SSH keys, AWS/GCP/Azure creds, kubeconfig, `.env` files |
| **Kubernetes lateral movement** | Service account tokens, `node-setup-*` pods in `kube-system` |
| **Node.js hooks** | `preinstall` / `postinstall` script detection in `package.json` |
| **Fork bomb indicator** | Python process count (exponential `.pth` re-trigger detection) |

**Rapid litellm sweep (single command):**

```bash
./collector.sh --quick --modules supply_chain
```

---

## 🚩 Flags

| Flag | Description |
|------|-------------|
| `--quick` | Reduces Unified Log collection window (6h→1h short, 24h→6h long) and line limits. Also available as `COLLECTOR_QUICK=1` env var. |
| `--modules mod1,mod2` | Comma-separated list of modules to run. Only specified modules are executed. |
| `--list-modules` | Prints available module names and exits. |

---

## 📦 Output Structure

```
{hostname}_{timestamp}.zip
├── metadata/
│   ├── collection_meta.txt        # Collector version, host, mode, modules
│   └── hashes_sha256.txt          # SHA-256 manifest of all collected files
├── system/
├── persistence/
├── accounts/
├── network/
├── remote_kvm/
├── security_agents/
├── browser/
│   ├── chrome_Default_History.db
│   ├── chrome_Default_History.db-wal
│   ├── chrome_Default_History.db-shm
│   ├── safari_History.db
│   └── ...
├── logs/
├── timeline/
└── supply_chain/
    ├── pth_litellm_init.txt
    ├── pth_all_site_packages.txt
    ├── pip_list_all.txt
    ├── pip_show_litellm.txt
    ├── sysmon_backdoor_ls.txt
    ├── sysmon_backdoor_content.txt
    ├── dns_litellm_cloud.txt
    ├── credential_file_timestamps.txt
    ├── k8s_check.txt
    └── ...
```

Only directories for enabled modules are created. The `metadata/` directory is always present.

---

## ✅ Integrity Verification

Every collection includes `metadata/hashes_sha256.txt` — a SHA-256 hash of every file in the archive, generated **before** packaging. To verify after extraction:

```bash
cd {extracted_directory}
shasum -a 256 -c metadata/hashes_sha256.txt
```

---

## 🎯 Design Principles

- **Zero dependencies.** No Python, no Ruby, no Homebrew packages. Pure bash + macOS built-in tools.
- **Timeout protection.** Every command runs with an individual timeout (default 120s, configurable per-command). Hung commands are terminated and tagged with `[timeout]` in output.
- **Non-destructive.** Read-only collection — no files are modified, no settings are changed on the target system.
- **Portable.** Single file, copy via `scp` / AirDrop / USB, run immediately.
- **Evidence-grade.** SHA-256 manifest for chain-of-custody documentation.

---

## 🔧 Extending the Collector

To add a new module:

1. Define a function named `module_{name}()` following the existing pattern
2. Add the module name to the `ALL_MODULES` variable
3. Add a description line to `--list-modules` output
4. Use `add_steps N` at the top of your function for accurate progress tracking
5. Use `capture`, `copy_if_exists`, or `copy_with_wal` helpers for collection

```bash
module_my_custom() {
  add_steps 3
  capture "some_command" "$WORK/my_custom/output.txt"
  capture "another_command" "$WORK/my_custom/other.txt"
  copy_if_exists "/path/to/artifact" "$WORK/my_custom/artifact.bin"
}
```

---

## ⚠️ Known Limitations

- **Full Disk Access (FDA):** Some artifacts (e.g., Safari history, Mail databases) require the Terminal or iTerm to have Full Disk Access granted in **System Settings → Privacy & Security → Full Disk Access**. Without FDA, these files will show `[skip] not found` or `Operation not permitted`.
- **Unified Log depth:** macOS Unified Log retention varies by system. On systems with heavy logging, older entries may already be rotated out even within the 24h window.
- **SIP-protected paths:** System Integrity Protection prevents access to certain system directories. Running with `sudo` helps, but some paths remain inaccessible by design.
- **Browser DB locks:** If a browser is actively running, copied database files may be in a partial-write state. The WAL/SHM copy mitigates this, but for forensic-grade browser analysis, consider closing the browser or using `sqlite3` `.clone` command.

---

## 🤝 Companion Platform

For a web-based **forensics platform** that ingests this collector's ZIP output, parses artifacts into a searchable evidence table, and generates DFIR PDF reports (with optional local Ollama / OpenAI assistance), see:

➡️ **[yushin-mac-forensics-platform](https://github.com/Juwon1405/yushin-mac-forensics-platform)**

---

## 📜 Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2026-03-25 | Modularized architecture, `--modules` selective execution, `supply_chain` module (litellm PyPI IOC), `--quick` CLI flag, WAL/SHM browser DB support, progress tracking overhaul |
| 1.0 | 2026-01 | Initial monolithic collector with system, persistence, network, browser, security agent, and remote KVM coverage |

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## ✍️ Author

**YuShin (優心 / Bang Juwon)** — DFIR practitioner, Tokyo.

> *"優한 品質, 心을 담은 도구."*
> Quality with care.

If this tool helped you, a ⭐ on the repo means a lot. Issues / PRs welcome.
