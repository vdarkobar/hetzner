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
