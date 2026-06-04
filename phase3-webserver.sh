#!/usr/bin/env bash
#
# ─────────────────────────────────────────────────────────────────────────────
#  phase3-webserver.sh
#  Hetzner Cloud — Debian 13 (trixie) — Phase 3 (nginx static site + TLS)
# ─────────────────────────────────────────────────────────────────────────────
#  Runs after phase 1 (cloud-init) and phase 2 (phase2-hardening.sh). Installs
#  nginx + certbot, deploys a set of static .html pages, issues a Let's Encrypt
#  certificate via the webroot method, writes a hardened TLS + headers config,
#  and wires up automatic renewal. Idempotent: safe to re-run after edits.
#
#  Ownership boundaries (do not cross):
#    • phase 1 owns  10-baseline SSH + 90-baseline sysctl + journald
#    • phase 2 owns  UFW (declarative reset), sudo policy, role drop-ins,
#                    fail2ban, unattended-upgrades
#    • phase 3 owns  nginx, the site vhost, TLS/header snippets, certbot
#
#  This script does NOT manage UFW. Ports 80/443 are phase 2's job — set
#  UFW_ALLOW_HTTP=1 and UFW_ALLOW_HTTPS=1 in phase2-hardening.sh and re-run it
#  BEFORE running this. (HTTP-01 validation needs 80 open to the world.)
#  Also open 80/443 inbound in the Hetzner Cloud Firewall (outer layer).
#
#  Execution:
#      sudo /usr/local/sbin/phase3-webserver.sh
#
#  Files this script owns (all marked "Managed by phase3-webserver.sh"):
#      /etc/nginx/conf.d/00-hardening.conf
#      /etc/nginx/snippets/tls-modern.conf
#      /etc/nginx/snippets/security-headers.conf
#      /etc/nginx/sites-available/<primary>.conf  (+ sites-enabled symlink)
#      /etc/letsencrypt/renewal-hooks/deploy/00-reload-nginx.sh
# ─────────────────────────────────────────────────────────────────────────────

set -Eeo pipefail

# ── Config ───────────────────────────────────────────────────────────────────

# Primary domain (cert lineage name + first SAN). MUST resolve to this host.
PRIMARY_DOMAIN="${PRIMARY_DOMAIN:-example.com}"

# Additional SANs served by the same site (e.g. the www alias). Bash array.
#   EXTRA_DOMAINS=( "www.example.com" )
EXTRA_DOMAINS=( "www.example.com" )

# Contact for the ACME account. Note: Let's Encrypt stopped sending expiry
# emails (June 2025) — this is for account recovery / urgent notices only.
# Monitor expiry yourself (the summary + runbook show how).
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@example.com}"

# Where your 8 .html pages currently sit (staging dir). Copied into the docroot.
SITE_SRC="${SITE_SRC:-/root/site}"
INDEX_FILE="${INDEX_FILE:-index.html}"

# rsync the docroot with --delete (declarative; removes files no longer in
# SITE_SRC). Off by default — guards against a mistyped SITE_SRC wiping content.
SYNC_DELETE="${SYNC_DELETE:-0}"

# ── TLS / header policy ──
ENABLE_HSTS="${ENABLE_HSTS:-1}"
HSTS_MAX_AGE="${HSTS_MAX_AGE:-63072000}"        # 2 years
HSTS_INCLUDE_SUBDOMAINS="${HSTS_INCLUDE_SUBDOMAINS:-1}"
HSTS_PRELOAD="${HSTS_PRELOAD:-0}"               # preload = hard commitment; off

# Mask the last octet of client IPv4 in the access log (privacy / data minimisation).
ANONYMIZE_LOG_IPS="${ANONYMIZE_LOG_IPS:-0}"

# ── Rate limiting + fail2ban (nginx-limit-req jail) ──
# Two toggles. The zone (RATELIMIT) throttles per-IP request rate at the nginx
# layer; the jail (FAIL2BAN_JAIL) bans IPs that sustain violations. The jail
# reads error.log (real client IP), so it works even with ANONYMIZE_LOG_IPS=1.
#
# Dependency: the jail watches limit_req violations, so it is meaningful ONLY
# when RATELIMIT=1. With JAIL=1 and RATELIMIT=0 the jail is SKIPPED (a warning
# is printed) — there would be no violations to act on.
#
#   RATELIMIT  JAIL   result
#       1       1     zone + limit_req + jail            (default)
#       1       0     zone + limit_req only (no bans)
#       0       0     nothing
#       0       1     jail skipped + warning
#
# fail2ban's daemon lifecycle is phase 2's domain (ENABLE_FAIL2BAN); the jail
# here is only a jail.d drop-in. If fail2ban is absent it is installed as a
# fallback so the script stays self-contained — but note Debian's packaging
# also enables the [sshd] jail by default. To run the nginx jail WITHOUT the
# sshd jail, either run phase 2 with ENABLE_FAIL2BAN=1 first, or drop a
# phase-2-owned /etc/fail2ban/jail.d/99-disable-sshd.local ([sshd]\nenabled=false)
# — a .local in jail.d overrides defaults-debian.conf by category.
ENABLE_NGINX_RATELIMIT="${ENABLE_NGINX_RATELIMIT:-1}"
ENABLE_NGINX_FAIL2BAN_JAIL="${ENABLE_NGINX_FAIL2BAN_JAIL:-1}"
RATE_LIMIT_RPS="${RATE_LIMIT_RPS:-10}"           # sustained req/s per IP (page traffic only)
RATE_LIMIT_BURST="${RATE_LIMIT_BURST:-20}"       # absorbs a normal multi-asset page load
F2B_MAXRETRY="${F2B_MAXRETRY:-10}"               # limit_req violations before ban
F2B_FINDTIME="${F2B_FINDTIME:-10m}"
F2B_BANTIME="${F2B_BANTIME:-1h}"

# ── certbot behaviour ──
STAGING="${STAGING:-0}"                          # 1 → LE staging CA (test, no rate limits)
FORCE_ISSUE="${FORCE_ISSUE:-0}"                  # 1 → re-issue even if a cert exists

# ── Misc ──
WRITE_RUNBOOK="${WRITE_RUNBOOK:-1}"              # generate /root/WEBSERVER-RUNBOOK.md
WRITE_MOTD="${WRITE_MOTD:-1}"                    # login MOTD note with the edit→re-run workflow
STATE_DIR="/var/lib/phase3-webserver"

# ── Derived ──
WEBROOT="/var/www/${PRIMARY_DOMAIN}/html"
ACME_WEBROOT="/var/www/_letsencrypt"
LE_LIVE="/etc/letsencrypt/live/${PRIMARY_DOMAIN}"
VHOST_AVAIL="/etc/nginx/sites-available/${PRIMARY_DOMAIN}.conf"
VHOST_ENABLED="/etc/nginx/sites-enabled/${PRIMARY_DOMAIN}.conf"
TLS_SNIPPET="/etc/nginx/snippets/tls-modern.conf"
HEADERS_SNIPPET="/etc/nginx/snippets/security-headers.conf"
HARDENING_CONF="/etc/nginx/conf.d/00-hardening.conf"
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/00-reload-nginx.sh"
F2B_NGINX_JAIL="/etc/fail2ban/jail.d/nginx.local"
MOTD_DROPIN="/etc/update-motd.d/30-webserver"
SERVER_NAMES="${PRIMARY_DOMAIN} ${EXTRA_DOMAINS[*]}"

# ── ERR trap ─────────────────────────────────────────────────────────────────

trap 'rc=$?; printf "\n[!] phase3-webserver failed (rc=%s) at line %s: %s\n" "$rc" "$LINENO" "$BASH_COMMAND" >&2; exit "$rc"' ERR

# ── Preflight: root + commands ───────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "[-] Must be run as root (use sudo)." >&2
  exit 1
fi

for cmd in systemctl apt-get awk getent curl rsync; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "[-] Required command missing: $cmd" >&2; exit 1; }
done

# ── Config validation ────────────────────────────────────────────────────────
# PRIMARY_DOMAIN and EXTRA_DOMAINS land in nginx server_name and certbot -d
# args; CERTBOT_EMAIL goes to the ACME account. Validate before any side effect.

hostname_re='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

if [[ "$PRIMARY_DOMAIN" == "example.com" ]]; then
  echo "[-] PRIMARY_DOMAIN is still the placeholder 'example.com' — edit the config block." >&2
  exit 1
fi
if [[ ! "$PRIMARY_DOMAIN" =~ $hostname_re ]]; then
  echo "[-] PRIMARY_DOMAIN '${PRIMARY_DOMAIN}' does not look like an FQDN." >&2
  exit 1
fi
for d in "${EXTRA_DOMAINS[@]}"; do
  [[ "$d" =~ $hostname_re ]] || { echo "[-] EXTRA_DOMAINS entry '${d}' is not a valid FQDN." >&2; exit 1; }
done
if [[ "$CERTBOT_EMAIL" == "admin@example.com" || ! "$CERTBOT_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  echo "[-] CERTBOT_EMAIL '${CERTBOT_EMAIL}' is the placeholder or malformed — edit the config block." >&2
  exit 1
fi
if [[ ! -d "$SITE_SRC" ]]; then
  echo "[-] SITE_SRC '${SITE_SRC}' does not exist. Stage your .html pages there." >&2
  exit 1
fi
if ! find "$SITE_SRC" -maxdepth 2 -type f -name '*.html' -print -quit | grep -q .; then
  echo "[-] No .html files found under SITE_SRC '${SITE_SRC}'." >&2
  exit 1
fi
if [[ ! -f "${SITE_SRC%/}/${INDEX_FILE}" ]]; then
  echo "[!] INDEX_FILE '${INDEX_FILE}' not found at top of SITE_SRC — '/' may 404 until present." >&2
fi

mkdir -p "$STATE_DIR"

# ── Preflight: prior phases ──────────────────────────────────────────────────

[[ -f /etc/ssh/sshd_config.d/10-baseline.conf ]] \
  || { echo "[-] phase 1 baseline missing (10-baseline.conf) — run cloud-init first." >&2; exit 1; }

if [[ -f /var/lib/phase2-hardening/last-run ]]; then
  echo "[+] phase 2 has run."
else
  echo "[!] No phase-2 marker found (/var/lib/phase2-hardening/last-run)."
  echo "    nginx will still work, but UFW + sudo policy are phase 2's job — run it."
fi

# ── Preflight: firewall (verify only — phase 2 owns UFW) ─────────────────────

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "[*] UFW active — verifying 80/443 are open..."
  ufw_status="$(ufw status)"
  for p in 80 443; do
    if ! grep -qE "(^|[[:space:]])${p}/tcp[[:space:]].*ALLOW" <<<"$ufw_status"; then
      echo "[-] UFW is active but ${p}/tcp is not allowed." >&2
      echo "    Set UFW_ALLOW_HTTP=1 and UFW_ALLOW_HTTPS=1 in phase2-hardening.sh and re-run it." >&2
      echo "    (HTTP-01 validation needs port 80 reachable from the public internet.)" >&2
      exit 1
    fi
  done
  echo "[+] UFW permits 80/tcp and 443/tcp."
else
  echo "[!] UFW inactive or absent — relying on the Hetzner Cloud Firewall for ingress filtering."
fi

# ── Preflight: DNS (best-effort, soft) ───────────────────────────────────────
# HTTP-01 needs the public internet to resolve each name to THIS host. On
# Hetzner Cloud the public IP is bound directly to the VM NIC, so the resolved
# A/AAAA should match a local address. Mismatch → warn, don't block (split DNS).

mapfile -t LOCAL_IPS < <(hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d')
for d in "$PRIMARY_DOMAIN" "${EXTRA_DOMAINS[@]}"; do
  resolved="$(getent ahosts "$d" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  if [[ -z "$resolved" ]]; then
    echo "[!] DNS: '${d}' does not resolve yet — issuance will fail until it does."
    continue
  fi
  match=0
  for ip in "${LOCAL_IPS[@]}"; do
    [[ " $resolved " == *" $ip "* ]] && match=1
  done
  [[ $match -eq 1 ]] \
    && echo "[+] DNS: ${d} → ${resolved}(local)" \
    || echo "[!] DNS: ${d} → ${resolved}— none match local IPs (${LOCAL_IPS[*]:-none}). Check before issuing."
done

# ── Install nginx + certbot ──────────────────────────────────────────────────

echo "[*] Installing nginx + certbot (distro packages)..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot >/dev/null
echo "[+] $(nginx -v 2>&1) / $(certbot --version 2>&1)"

# ── Deploy site content ──────────────────────────────────────────────────────

echo "[*] Deploying site content → ${WEBROOT}"
mkdir -p "$WEBROOT" "$ACME_WEBROOT/.well-known/acme-challenge"

rsync_opts=(-a)
[[ "$SYNC_DELETE" -eq 1 ]] && rsync_opts+=(--delete)
rsync "${rsync_opts[@]}" "${SITE_SRC%/}/" "${WEBROOT%/}/"

# Content owned by root, world-readable, NOT writable by the nginx worker.
chown -R root:root "$WEBROOT"
find "$WEBROOT" -type d -exec chmod 0755 {} +
find "$WEBROOT" -type f -exec chmod 0644 {} +
chown -R root:root "$ACME_WEBROOT"
chmod -R 0755 "$ACME_WEBROOT"
echo "[+] $(find "$WEBROOT" -type f | wc -l) file(s) deployed."

# ── nginx global hardening (http context) ────────────────────────────────────

echo "[*] Writing ${HARDENING_CONF}"
cat >"$HARDENING_CONF" <<'EOF'
# Managed by phase3-webserver.sh — do not hand-edit; re-run the script.
# Global hardening for a small static site (http context).

server_tokens off;            # hide nginx version in errors + Server header
client_max_body_size 1m;      # static site: no large uploads expected
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 30s;
EOF

if [[ "$ANONYMIZE_LOG_IPS" -eq 1 ]]; then
  cat >>"$HARDENING_CONF" <<'EOF'

# Privacy: mask the last IPv4 octet / last IPv6 group before logging.
map $remote_addr $remote_addr_anon {
    ~(?P<ip>\d+\.\d+\.\d+)\.    $ip.0;
    ~(?P<ip>[^:]+:[^:]+):       $ip::;
    default                     0.0.0.0;
}
log_format anon '$remote_addr_anon - - [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log anon;
EOF
fi

if [[ "$ENABLE_NGINX_RATELIMIT" -eq 1 ]]; then
  # limit_req zone (http context). Keyed on client IP. Violations are logged to
  # error.log with the real client IP — that's what the fail2ban jail reads.
  # 429 is cleaner than the default 503 for a throttled client.
  printf '\n# Per-IP request rate limiting (applied in location / of the vhost).\nlimit_req_zone $binary_remote_addr zone=staticlimit:10m rate=%dr/s;\nlimit_req_status 429;\n' \
    "$RATE_LIMIT_RPS" >>"$HARDENING_CONF"
fi

# ── TLS snippet (Mozilla "intermediate"; no OCSP stapling) ───────────────────

echo "[*] Writing ${TLS_SNIPPET}"
cat >"$TLS_SNIPPET" <<'EOF'
# Managed by phase3-webserver.sh — included in the HTTPS server block.
# Mozilla "intermediate" profile: TLS 1.2 + 1.3.
#
# OCSP stapling is intentionally OMITTED. Let's Encrypt removed OCSP URLs from
# certificates (7 May 2025) and shut down its OCSP responders (6 Aug 2025), so
# "ssl_stapling on" would only emit:
#     "ssl_stapling" ignored, no OCSP responder URL in the certificate
# Revocation is handled client-side via CRLs. Do not re-add ssl_stapling.

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;
EOF

# ── Security headers snippet (server context; HSTS conditional) ──────────────
# NOTE: nginx add_header inheritance is all-or-nothing — if ANY location block
# adds its own add_header, these stop applying there. Keep add_header OUT of
# locations (the asset cache block below uses only `expires`, which is safe).

echo "[*] Writing ${HEADERS_SNIPPET}"
cat >"$HEADERS_SNIPPET" <<'EOF'
# Managed by phase3-webserver.sh — included in the HTTPS server block.
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()" always;
# CSP tuned for a self-contained static site (no external CDN). 'unsafe-inline'
# on style-src is a pragmatic concession for inline <style>; drop it once styles
# move to external .css files. Adjust if you add fonts/scripts from elsewhere.
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests" always;
EOF

if [[ "$ENABLE_HSTS" -eq 1 ]]; then
  hsts="max-age=${HSTS_MAX_AGE}"
  [[ "$HSTS_INCLUDE_SUBDOMAINS" -eq 1 ]] && hsts="${hsts}; includeSubDomains"
  [[ "$HSTS_PRELOAD" -eq 1 ]]            && hsts="${hsts}; preload"
  printf '# HSTS (ENABLE_HSTS=1). HTTPS responses only.\nadd_header Strict-Transport-Security "%s" always;\n' "$hsts" >>"$HEADERS_SNIPPET"
fi

# ── Issue certificate (webroot) if needed ────────────────────────────────────
# Bootstrap an HTTP-only vhost just long enough for HTTP-01, then issue.
# Skipped entirely on re-run when a cert already exists (no HTTPS blip).

cert_d_args=()
for d in "$PRIMARY_DOMAIN" "${EXTRA_DOMAINS[@]}"; do cert_d_args+=( -d "$d" ); done

if [[ ! -f "${LE_LIVE}/fullchain.pem" || "$FORCE_ISSUE" -eq 1 ]]; then
  echo "[*] No certificate yet (or FORCE_ISSUE=1) — bootstrapping HTTP vhost for ACME..."

  cat >/tmp/phase3-bootstrap.conf <<'TPL'
# Managed by phase3-webserver.sh — transient ACME bootstrap.
server {
    listen 80;
    listen [::]:80;
    server_name @@SERVER_NAMES@@;

    location ^~ /.well-known/acme-challenge/ {
        root @@ACME_WEBROOT@@;
        default_type "text/plain";
        try_files $uri =404;
    }
    location / { return 404; }
}
TPL
  sed -e "s|@@SERVER_NAMES@@|${SERVER_NAMES}|g" \
      -e "s|@@ACME_WEBROOT@@|${ACME_WEBROOT}|g" \
      /tmp/phase3-bootstrap.conf >"$VHOST_AVAIL"
  rm -f /tmp/phase3-bootstrap.conf

  ln -sf "$VHOST_AVAIL" "$VHOST_ENABLED"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl reload nginx 2>/dev/null || systemctl restart nginx

  certbot_args=( certonly --webroot -w "$ACME_WEBROOT" "${cert_d_args[@]}"
                 --cert-name "$PRIMARY_DOMAIN" --key-type ecdsa
                 --email "$CERTBOT_EMAIL" --agree-tos --no-eff-email -n )
  [[ "$STAGING" -eq 1 ]] && certbot_args+=( --staging )

  echo "[*] Requesting certificate via certbot..."
  certbot "${certbot_args[@]}"
  echo "[+] Certificate obtained: ${LE_LIVE}/fullchain.pem"
else
  echo "[+] Certificate already present at ${LE_LIVE} — skipping issuance."
fi

# ── Write the hardened HTTPS vhost ───────────────────────────────────────────

echo "[*] Writing hardened vhost → ${VHOST_AVAIL}"
cat >/tmp/phase3-vhost.conf <<'TPL'
# Managed by phase3-webserver.sh — do not hand-edit; re-run the script.
# Static site for: @@SERVER_NAMES@@

server {
    listen 80;
    listen [::]:80;
    server_name @@SERVER_NAMES@@;

    # Keep ACME reachable over HTTP so webroot renewals work without downtime.
    location ^~ /.well-known/acme-challenge/ {
        root @@ACME_WEBROOT@@;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name @@SERVER_NAMES@@;

    root  @@WEBROOT@@;
    index @@INDEX@@;

    ssl_certificate     @@FULLCHAIN@@;
    ssl_certificate_key @@PRIVKEY@@;

    include snippets/tls-modern.conf;
    include snippets/security-headers.conf;

    # Static-asset caching. `expires` does NOT reset add_header inheritance,
    # so the security headers above still apply here.
    location ~* \.(?:css|js|ico|gif|jpe?g|png|svg|webp|woff2?)$ {
        expires 7d;
        access_log off;
    }

    location / {
        @@LIMIT_REQ@@
        try_files $uri $uri/ =404;
    }

    # Block dotfiles (editor backups, .git, etc.) but keep ACME reachable.
    location ~ /\.(?!well-known) {
        deny all;
    }
}
TPL
# limit_req lives in `location /` only — page/probe traffic is throttled, but
# the asset location (where legit multi-request bursts happen) is exempt.
if [[ "$ENABLE_NGINX_RATELIMIT" -eq 1 ]]; then
  limit_req_line="limit_req zone=staticlimit burst=${RATE_LIMIT_BURST} nodelay;"
else
  limit_req_line=""
fi
sed -e "s|@@SERVER_NAMES@@|${SERVER_NAMES}|g" \
    -e "s|@@ACME_WEBROOT@@|${ACME_WEBROOT}|g" \
    -e "s|@@WEBROOT@@|${WEBROOT}|g" \
    -e "s|@@INDEX@@|${INDEX_FILE}|g" \
    -e "s|@@LIMIT_REQ@@|${limit_req_line}|g" \
    -e "s|@@FULLCHAIN@@|${LE_LIVE}/fullchain.pem|g" \
    -e "s|@@PRIVKEY@@|${LE_LIVE}/privkey.pem|g" \
    /tmp/phase3-vhost.conf >"$VHOST_AVAIL"
rm -f /tmp/phase3-vhost.conf

ln -sf "$VHOST_AVAIL" "$VHOST_ENABLED"
rm -f /etc/nginx/sites-enabled/default

# ── Renewal: deploy hook + timer ─────────────────────────────────────────────

echo "[*] Installing renewal deploy hook → ${DEPLOY_HOOK}"
mkdir -p "$(dirname "$DEPLOY_HOOK")"
cat >"$DEPLOY_HOOK" <<'EOF'
#!/bin/sh
# Managed by phase3-webserver.sh. Runs ONLY after a successful renewal.
# Validate config first so a bad edit can't take nginx down on reload.
nginx -t && systemctl reload nginx
EOF
chmod 0755 "$DEPLOY_HOOK"

# Debian enables certbot.timer on install; assert it anyway (idempotent).
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

# ── Enable, test, reload ─────────────────────────────────────────────────────

echo "[*] Validating and (re)loading nginx..."
nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reload nginx 2>/dev/null || systemctl restart nginx

# ── fail2ban: nginx-limit-req jail (drop-in) ─────────────────────────────────
# Daemon lifecycle belongs to phase 2 (ENABLE_FAIL2BAN). This contributes only
# a jail.d drop-in — exactly like phase 2's jail.d/sshd.local. The jail reads
# error.log (real client IP, unaffected by ANONYMIZE_LOG_IPS) and bans IPs that
# repeatedly trip the limit_req zone. Bans cover http,https only (SSH untouched).
# Requires the limit_req zone (ENABLE_NGINX_RATELIMIT=1) — nothing to ban without it.

if [[ "$ENABLE_NGINX_FAIL2BAN_JAIL" -eq 1 && "$ENABLE_NGINX_RATELIMIT" -ne 1 ]]; then
  echo "[!] ENABLE_NGINX_FAIL2BAN_JAIL=1 but ENABLE_NGINX_RATELIMIT=0 — no limit_req"
  echo "    zone is configured, so the jail would have no violations to act on. Skipping jail."
fi

if [[ "$ENABLE_NGINX_FAIL2BAN_JAIL" -eq 1 && "$ENABLE_NGINX_RATELIMIT" -eq 1 ]]; then
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    echo "[!] fail2ban not installed — installing as a fallback (its home is phase 2)."
    echo "    Note: Debian's default also enables the [sshd] jail; manage that in phase 2."
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null
  fi

  echo "[*] Writing ${F2B_NGINX_JAIL}"
  mkdir -p /etc/fail2ban/jail.d
  cat >"$F2B_NGINX_JAIL" <<EOF
# Managed by phase3-webserver.sh. nginx rate-limit jail.
# Reads error.log (real client IP) so it works with masked access logs.
[nginx-limit-req]
enabled  = true
filter   = nginx-limit-req
backend  = polling
logpath  = /var/log/nginx/error.log
port     = http,https
maxretry = ${F2B_MAXRETRY}
findtime = ${F2B_FINDTIME}
bantime  = ${F2B_BANTIME}
EOF
  chmod 0644 "$F2B_NGINX_JAIL"

  # Unconditional: start + enable even if fail2ban was already installed but stopped.
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
  echo "[+] fail2ban nginx-limit-req jail active."
fi

# ── Health checks ────────────────────────────────────────────────────────────

echo "[*] Health checks..."
systemctl is-active --quiet nginx && echo "[+] nginx active." || { echo "[-] nginx not active." >&2; exit 1; }

code_https="$(curl -fsS -o /dev/null -w '%{http_code}' \
  --resolve "${PRIMARY_DOMAIN}:443:127.0.0.1" "https://${PRIMARY_DOMAIN}/" 2>/dev/null || true)"
code_http="$(curl -s -o /dev/null -w '%{http_code}' \
  --resolve "${PRIMARY_DOMAIN}:80:127.0.0.1" "http://${PRIMARY_DOMAIN}/" 2>/dev/null || true)"

echo "[+] HTTPS GET / → ${code_https:-no-response}"
echo "[+] HTTP  GET / → ${code_http:-no-response} (expect 301)"

if [[ "$ENABLE_NGINX_FAIL2BAN_JAIL" -eq 1 && "$ENABLE_NGINX_RATELIMIT" -eq 1 ]] && command -v fail2ban-client >/dev/null 2>&1; then
  jail_line="$(fail2ban-client status nginx-limit-req 2>/dev/null | awk -F'\t' '/Currently banned/{print $2}' || true)"
  echo "[+] fail2ban nginx-limit-req: currently banned = ${jail_line:-0}"
fi

echo "[*] Dry-run renewal (validates webroot + deploy hook):"
certbot renew --dry-run 2>&1 | tail -n 4 | sed 's/^/    /' || echo "    [!] dry-run reported issues — inspect /var/log/letsencrypt/"

# ── Runbook ──────────────────────────────────────────────────────────────────

if [[ "$WRITE_RUNBOOK" -eq 1 ]]; then
  cat >/root/WEBSERVER-RUNBOOK.md <<EOF
# Web server runbook — ${PRIMARY_DOMAIN}

Generated by phase3-webserver.sh on $(date -Iseconds).

## What's where
- Site content (docroot) : ${WEBROOT}
- Staging source         : ${SITE_SRC}
- Site vhost             : ${VHOST_AVAIL}
- TLS knobs              : ${TLS_SNIPPET}
- Security headers       : ${HEADERS_SNIPPET}
- Global hardening       : ${HARDENING_CONF}
- Certificate (live)     : ${LE_LIVE}/
- Renewal deploy hook    : ${DEPLOY_HOOK}
- Rate-limit + jail       : ${HARDENING_CONF} (zone) + ${F2B_NGINX_JAIL}

## Update the pages
1. Drop new/changed .html into ${SITE_SRC}
2. sudo /usr/local/sbin/phase3-webserver.sh   # re-syncs + re-applies perms
   (set SYNC_DELETE=1 to also remove files no longer in the staging dir)

## Rate limiting + fail2ban
- Rate limit (zone): $([[ $ENABLE_NGINX_RATELIMIT -eq 1 ]] && echo "${RATE_LIMIT_RPS} r/s per IP, burst ${RATE_LIMIT_BURST} (location / only; assets exempt)" || echo "off")
- Jail            : $([[ $ENABLE_NGINX_FAIL2BAN_JAIL -eq 1 && $ENABLE_NGINX_RATELIMIT -eq 1 ]] && echo "on — bans after ${F2B_MAXRETRY} violations in ${F2B_FINDTIME}, for ${F2B_BANTIME} (http,https)" || echo "off")
- Status : sudo fail2ban-client status nginx-limit-req
- Unban  : sudo fail2ban-client set nginx-limit-req unbanip <IP>
- Violations are logged to /var/log/nginx/error.log ("limiting requests").
- The jail reads error.log, so it keeps working with ANONYMIZE_LOG_IPS=1.
- Toggles: ENABLE_NGINX_RATELIMIT (zone), ENABLE_NGINX_FAIL2BAN_JAIL (ban).
  The jail needs the zone; JAIL=1 with RATELIMIT=0 is skipped.
- nginx jail WITHOUT the Debian sshd jail: run phase 2 with ENABLE_FAIL2BAN=1
  first, OR drop /etc/fail2ban/jail.d/99-disable-sshd.local containing
  "[sshd]" then "enabled = false" (a .local in jail.d overrides defaults-debian.conf).

## Certificates
- Auto-renewal: certbot.timer (twice daily, renews at <=30 days left)
- Status      : systemctl list-timers certbot.timer
- Check expiry: openssl x509 -in ${LE_LIVE}/fullchain.pem -noout -enddate
- Force renew : sudo certbot renew --force-renewal --cert-name ${PRIMARY_DOMAIN}
- Dry run     : sudo certbot renew --dry-run
- Note: Let's Encrypt no longer emails expiry warnings — monitor it yourself.

## Firewall (phase 2 owns UFW)
- 80/443 are opened by setting UFW_ALLOW_HTTP=1 / UFW_ALLOW_HTTPS=1 in
  phase2-hardening.sh and re-running it. Also open 80/443 in the Hetzner
  Cloud Firewall. Re-running phase 2 with the toggles off will close them.

## Verify externally
- https://www.ssllabs.com/ssltest/analyze.html?d=${PRIMARY_DOMAIN}
- https://securityheaders.com/?q=${PRIMARY_DOMAIN}
EOF
  echo "[+] Runbook written to /root/WEBSERVER-RUNBOOK.md"
fi

# ── Login MOTD note (surgical drop-in; existing motd scripts untouched) ──────
# Single numbered drop-in, not the LXC wipe-and-rebuild — this is an existing
# VM. Paths are baked in at write time, so re-running refreshes them.

if [[ "$WRITE_MOTD" -eq 1 ]]; then
  echo "[*] Writing login MOTD note → ${MOTD_DROPIN}"
  mkdir -p /etc/update-motd.d
  cat >"$MOTD_DROPIN" <<EOF
#!/bin/sh
# Managed by phase3-webserver.sh — do not hand-edit; re-run the script.
printf '\n  Web server: ${PRIMARY_DOMAIN}\n'
printf '  ────────────────────────────────────────────────────────\n'
printf '  Workflow:  edit pages in ${SITE_SRC}\n'
printf '             re-run  sudo /usr/local/sbin/phase3-webserver.sh\n'
printf '             it pushes the changes into the docroot:\n'
printf '             ${WEBROOT}\n'
printf '  ────────────────────────────────────────────────────────\n\n'
EOF
  chmod 0755 "$MOTD_DROPIN"
  echo "[+] MOTD note written (shown on next SSH login)."
elif [[ -f "$MOTD_DROPIN" ]]; then
  rm -f "$MOTD_DROPIN"
  echo "[+] Removed MOTD note (WRITE_MOTD=0)."
fi

# ── Summary ──────────────────────────────────────────────────────────────────

date -Iseconds > "$STATE_DIR/last-run"

cert_expiry="n/a"
if command -v openssl >/dev/null 2>&1 && [[ -f "${LE_LIVE}/fullchain.pem" ]]; then
  cert_expiry="$(openssl x509 -in "${LE_LIVE}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
fi
timer_state="$(systemctl is-active certbot.timer 2>/dev/null || true)"

echo
echo "── phase3-webserver summary ─────────────────────────────────────────────"
echo "  domains      : ${SERVER_NAMES}"
echo "  docroot      : ${WEBROOT}"
echo "  vhost        : ${VHOST_AVAIL}"
echo "  TLS          : TLSv1.2+1.3, Mozilla intermediate (no OCSP stapling)"
echo "  HSTS         : $([[ $ENABLE_HSTS -eq 1 ]] && echo "on (max-age=${HSTS_MAX_AGE}$([[ $HSTS_PRELOAD -eq 1 ]] && echo ', preload'))" || echo off)"
echo "  log IP mask  : $([[ $ANONYMIZE_LOG_IPS -eq 1 ]] && echo on || echo off)"
echo "  rate limit   : $([[ $ENABLE_NGINX_RATELIMIT -eq 1 ]] && echo "${RATE_LIMIT_RPS}r/s burst ${RATE_LIMIT_BURST} (location / )" || echo off)"
echo "  nginx jail   : $([[ $ENABLE_NGINX_FAIL2BAN_JAIL -eq 1 && $ENABLE_NGINX_RATELIMIT -eq 1 ]] && echo "on (maxretry ${F2B_MAXRETRY}/${F2B_FINDTIME}, ban ${F2B_BANTIME})" || echo off)"
echo "  certificate  : $([[ $STAGING -eq 1 ]] && echo 'STAGING (not trusted!)' || echo 'production')"
echo "  cert expiry  : ${cert_expiry}"
echo "  renew timer  : ${timer_state:-unknown}"
echo "  MOTD note    : $([[ $WRITE_MOTD -eq 1 ]] && echo on || echo off)"
echo "  HTTPS / HTTP : ${code_https:-?} / ${code_http:-?}"
echo "  last run     : $(cat "$STATE_DIR/last-run")"
echo "─────────────────────────────────────────────────────────────────────────"
[[ "$STAGING" -eq 1 ]] && echo "  [!] STAGING cert issued — browsers will NOT trust it. Re-run with STAGING=0."
echo
