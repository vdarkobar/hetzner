# Debian 13 (Trixie) Host Hardening for Hetzner Cloud

> **Scope:** this hardens the **host** (the operating system and its baseline) —
> not the applications you later run on it. A hardened host running a vulnerable
> service is still a vulnerable server. Treat this as the foundation you build
> service-level security (TLS, web stack, WAF, app auth, backups, log shipping)
> on top of, not as a substitute for it.

Two-phase bootstrap and hardening for a public Debian 13 VM on Hetzner Cloud.
Phase 1 (`cloud-init.yaml`) sets the baseline declaratively on first boot;
phase 2 (`phase2-hardening.sh`) verifies that baseline and layers on
role-specific tightening, a host firewall, and optional Fail2ban.

The design is provider-agnostic for the Debian hardening itself; the delivery
model (single 32 KiB user-data paste) and the "Hetzner Cloud Firewall is the
outer layer" assumption are Hetzner-specific.

### `cloud-init.yaml` — runs once on first boot

- Sets hostname, FQDN, timezone (`Europe/Berlin`), and locale (`en_US.UTF-8`)
- Disables SSH password authentication globally via `ssh_pwauth: false`
- Manages only the hostname/FQDN line in `/etc/hosts` (`manage_etc_hosts: localhost`)
- Creates the admin user with `sudo` group, bash shell, locked password, and `NOPASSWD:ALL` sudo (the bootstrap default — phase 2 switches this to password-gated)
- Installs the SSH public key for the admin user
- Runs `apt update`, `apt upgrade`, and reboots if the kernel/initramfs requires it
- Installs baseline packages: `ca-certificates`, `unattended-upgrades`, `apt-listchanges`, `needrestart`, `curl`, `gnupg`, `git`, `rsync`, `less`, `htop`, `jq`
- Writes `/etc/ssh/sshd_config.d/10-baseline.conf` (no root login, no passwords, no keyboard-interactive, pubkey only, `UsePAM yes`, `MaxAuthTries 3`, `MaxSessions 4`, `X11Forwarding no`, `PermitUserEnvironment no`)
- Writes `/etc/sysctl.d/90-baseline.conf` (rp_filter, no ICMP redirects, no source routing, SYN cookies, log martians, `fs.protected_*`, `kptr_restrict`, `dmesg_restrict`, `unprivileged_bpf_disabled`)
- Writes `/etc/tmpfiles.d/journal-persistent.conf` to enable persistent journald storage in `/var/log/journal`
- Writes `/etc/apt/apt.conf.d/52unattended-upgrades-local` with local upgrade policy (remove unused deps + kernels, no automatic reboot)
- Drops `phase2-hardening.sh` onto disk at `/usr/local/sbin/phase2-hardening.sh` with mode `0755` — does **not** execute it
- Validates SSH config with `sshd -t`
- Triggers tmpfiles to create `/var/log/journal`, then `journalctl --flush` to move logs into persistent storage
- Applies the sysctl baseline via `sysctl --system`
- Reloads SSH to pick up the drop-in
- Enables and starts `unattended-upgrades.service`
- Prints a `final_message` telling you to SSH in as the admin user and run phase 2 manually

### `phase2-hardening.sh` — runs manually after SSH login, idempotent (re-runnable)

- Refuses to run unless invoked via `sudo` as the admin user (not as root directly)
- Checks required commands are present: `cloud-init`, `sshd`, `sysctl`, `journalctl`, `systemctl`, `apt-get`, `awk`
- Verifies cloud-init finished cleanly (`done` or `disabled`); aborts if `running`, `error`, or `degraded`
- Verifies the SSH baseline drop-in exists and that `sshd -T` reports every expected directive at its exact expected value
- Verifies `/var/log/journal` exists; if missing, re-creates it and flushes
- Verifies the sysctl baseline file exists and that every key (including both `all.*` and `default.*`) matches its expected value — aborts on any drift
- Switches the admin user to **password-gated sudo by default** (`SUDO_REQUIRE_PASSWORD=1`): prompts to set the account password (used for sudo only — SSH login stays key-only), then removes cloud-init's `NOPASSWD` grant so the user falls back to Debian's stock password-required `%sudo` rule. Sets the password *before* removing `NOPASSWD` and verifies the `sudo`-group + `%sudo`-rule fallback exists first, to avoid lockout. Requires an interactive terminal; set `SUDO_REQUIRE_PASSWORD=0` to keep passwordless sudo
- Optionally writes `/etc/ssh/sshd_config.d/50-role-<role>.conf` with `AllowUsers`, `DisableForwarding yes`, and narrow `PubkeyAcceptedAlgorithms` (Ed25519 + FIDO2 only), validates it, and reloads SSH — gated by `ROLE` + `APPLY_ROLE_SSH_TIGHTENING`
- Optionally creates `/etc/sysctl.d/95-role-<role>.conf` for role-specific kernel tweaks — gated by `ROLE` + `APPLY_ROLE_SYSCTL`
- Detaches UFW from sysctl management (`IPT_SYSCTL=""`) so the firewall stops overwriting the baseline kernel knobs
- Installs and configures UFW (default deny inbound, allow outbound, allow SSH from `ADMIN_SSH_ALLOW_CIDRS` if set or all sources otherwise, optional HTTP/HTTPS), then enables it — declarative via `ufw --force reset` so re-runs converge to the configured state
- Optionally installs Fail2ban (with `python3-systemd`) and a local `sshd.local` jail using the systemd backend — gated by `ENABLE_FAIL2BAN` (off by default, since key-only SSH plus OpenSSH 10's `PerSourcePenalties` makes it largely cosmetic)
- Ensures `unattended-upgrades.service` is enabled and runs `unattended-upgrade --dry-run` to validate the policy
- Writes a timestamp to `/var/lib/phase2-hardening/last-run`
- Prints a summary block with admin user, role state, UFW/Fail2ban state, journald state, and last-run timestamp

### Drop-in numbering

The two config directories have **opposite** precedence rules:

| Directory | Precedence | Baseline | Role | Manual override |
|---|---|---|---|---|
| `sshd_config.d` | first-match-wins (lower number wins) | `10-baseline.conf` | `50-role-<role>.conf` | `01-local.conf` |
| `sysctl.d` | last-write-wins (higher number wins) | `90-baseline.conf` | `95-role-<role>.conf` | `99-local.conf` |

The sysctl baseline must sit above `50` because Debian ships its defaults in
`/usr/lib/sysctl.d/50-default.conf` and last write wins.

## Usage

1. Edit the values in the `EDIT THESE` block at the top of `cloud-init.yaml`: `hostname`, `fqdn` (delete the line entirely if no FQDN is planned), the admin `name`, and the SSH public key line. Everything below the `DO NOT EDIT BELOW` divider is the baseline and normally needs no changes.
2. Validate locally: `cloud-init schema --config-file cloud-init.yaml`.
3. Create the server in the Hetzner Console with an SSH key and a Cloud Firewall attached, and paste `cloud-init.yaml` into the Cloud Config field.
4. After first boot, SSH in and run phase 2:

   ```bash
   ssh <admin>@<server-ip>
   sudo /usr/local/sbin/phase2-hardening.sh
   ```

   Edit the config block at the top of the script first to set `ROLE`, `ADMIN_SSH_ALLOW_CIDRS`, `UFW_ALLOW_HTTP/HTTPS`, `ENABLE_FAIL2BAN`, `SUDO_REQUIRE_PASSWORD` (on by default), and the role-apply flags. Run it from an interactive session, since password-gated sudo prompts for a password. After it runs, verify in a second session with `sudo -k; sudo true` before logging out.
