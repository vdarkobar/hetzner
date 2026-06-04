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
