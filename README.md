# Quick Start — Debian 13 on Hetzner Cloud  
  
  
> **Scope:** phases 1–2 harden the **host** (the OS and its baseline); phase 3 adds a
> hardened **static-site layer** on top — nginx, auto-renewing Let's Encrypt TLS, a
> modern cipher config, security headers, per-IP rate limiting, and a Fail2ban jail.  
> Together they're a foundation, not a complete security program.  
> A hardened host and valid TLS won't save a vulnerable application: phase 3 serves
> **static content only**, and the moment you put a dynamic app behind it (a backend,
> a CMS, or server-side form handling) you reintroduce application attack surface —
> injection, auth, sessions, dependency CVEs — that none of these phases address.  
> Rate limiting is not a WAF. Backups, monitoring and alerting, log shipping, and
> application-level auth remain yours to build on top.

The design is provider-agnostic for the Debian hardening and the nginx/TLS layer
itself; the delivery model — a single cloud-init user-data paste (~32 KiB, carrying the
phase-2 script inline) — and the two-layer firewall assumption (Hetzner Cloud Firewall
as the outer layer, UFW as the inner) are Hetzner-specific.
  
<br>
  
Three phases, run in order. Phase 1 sets the baseline on first boot; phase 2
hardens the host; phase 3 serves a static site over HTTPS.

| Phase | File | Runs |
|---|---|---|
| 1 | `cloud-init.yaml` | once, automatically on first boot |
| 2 | `phase2-hardening.sh` | manually, after SSH login |
| 3 | `phase3-webserver.sh` | manually, when you want to host a site |

---

## Phase 1 — baseline (cloud-init)

1. Edit the `EDIT THESE` block at the top of `cloud-init.yaml`: `hostname`,
   `fqdn` (delete the line if none), the admin `name`, and your SSH public key.
2. Validate locally:
   ```bash
   cloud-init schema --config-file cloud-init.yaml
   ```
3. In the Hetzner Console, create the server with an **SSH key** and a **Cloud
   Firewall** attached, and paste `cloud-init.yaml` into the *Cloud config* field.

First boot applies SSH/sysctl hardening, persistent journald, and
unattended-upgrades, and drops `phase2-hardening.sh` into `/usr/local/sbin/`.

---

## Phase 2 — hardening

SSH in as your admin user, then:

1. Edit the config block. For a web host:
   ```bash
   sudo nano /usr/local/sbin/phase2-hardening.sh
   #   ROLE="webserver"
   #   APPLY_ROLE_SSH_TIGHTENING=1
   #   UFW_ALLOW_HTTP=1
   #   UFW_ALLOW_HTTPS=1
   #   ENABLE_FAIL2BAN=1   # optional, but lets phase 3 reuse the daemon
   ```
2. Run it (it prompts you to set a sudo password by default):
   ```bash
   sudo /usr/local/sbin/phase2-hardening.sh
   ```
3. Before logging out, verify sudo still works in a **second** session:
   ```bash
   sudo -k; sudo true
   ```

`UFW_ALLOW_HTTP/HTTPS=1` opens 80/443 in the host firewall — phase 3 needs this.

---

## Phase 3 — static site + HTTPS

**Prerequisites** (phase 3 only warns on these; they cause cert failures, not a clean stop):

- DNS for your domain (and `www`) resolves to the server's public IP.
- Ports **80 and 443 open in the Hetzner Cloud Firewall** (the outer layer).
- Phase 2 ran with `UFW_ALLOW_HTTP/HTTPS=1` (the inner layer).

Steps:

1. Install the script:
   ```bash
   sudo wget -O /usr/local/sbin/phase3-webserver.sh \
     https://raw.githubusercontent.com/vdarkobar/hetzner/main/phase3-webserver.sh
   sudo chmod 0755 /usr/local/sbin/phase3-webserver.sh
   ```
2. First run creates the staging dir and stops:
   ```bash
   sudo /usr/local/sbin/phase3-webserver.sh
   # → creates /home/<you>/site (owned by you)
   ```
3. Upload your pages from your local machine (`index.html` at the top):
   ```bash
   scp -r ./site/* <you>@<host>:/home/<you>/site/
   ```
4. Set the domain/email — either edit the config block, or pass them inline.
   Do a `STAGING=1` rehearsal first (untrusted cert, no rate limits):
   ```bash
   sudo STAGING=1 \
        PRIMARY_DOMAIN=yourdomain.tld \
        EXTRA_DOMAINS="www.yourdomain.tld" \
        CERTBOT_EMAIL=you@yourdomain.tld \
        /usr/local/sbin/phase3-webserver.sh
   ```
5. When the staging run and its `certbot renew --dry-run` are clean, switch to a
   real (trusted) certificate:
   ```bash
   sudo certbot delete --cert-name yourdomain.tld
   sudo PRIMARY_DOMAIN=yourdomain.tld \
        EXTRA_DOMAINS="www.yourdomain.tld" \
        CERTBOT_EMAIL=you@yourdomain.tld \
        /usr/local/sbin/phase3-webserver.sh
   ```

To update the site later: drop new files in `/home/<you>/site` and re-run phase 3.

Renewal is automatic (`certbot.timer`, twice daily). Verify externally:
`https://www.ssllabs.com/ssltest/` and `https://securityheaders.com/`.

---

### Notes

- All three scripts are **idempotent** — safe to re-run after editing config.
- Config values can be set in each script's top block **or** passed as env vars
  (`EXTRA_DOMAINS` is space-separated; empty `EXTRA_DOMAINS=""` means no `www`).
- Phase 2 owns UFW; phase 3 only verifies 80/443 are open. Re-running phase 2
  with the HTTP/HTTPS toggles off will close them again.
