#!/usr/bin/env bash
# ==============================================================================
# CyberGuard Anti-Hardening Degradation Script (Linux / Ubuntu)
# Purpose: Intentionally weakens VM security configuration to establish a
#          "dirty baseline" with near-zero passed CIS rules for ML training.
# CAUTION: Preserves Vagrant SSH key authentication and sudo access.
# ==============================================================================

set -e

echo "[*] Starting CyberGuard Anti-Hardening Degradation..."

# ------------------------------------------------------------------------------
# 1. Sysctl & Kernel Security Parameters (Chapter 1 & 3)
# ------------------------------------------------------------------------------
echo "[+] Degrading kernel sysctl security parameters..."
cat << 'EOF' > /etc/sysctl.d/99-cis-degrade.conf
# Insecure networking defaults
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_ignore_bogus_error_responses = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.tcp_syncookies = 0

# Insecure memory & coredump settings
fs.suid_dumpable = 1
kernel.randomize_va_space = 0
EOF

sysctl --system >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 2. Disable Firewalls and Mandatory Access Controls (Chapter 1 & 4)
# ------------------------------------------------------------------------------
echo "[+] Disabling UFW firewall and AppArmor..."
ufw disable >/dev/null 2>&1 || true
systemctl stop ufw >/dev/null 2>&1 || true
systemctl disable ufw >/dev/null 2>&1 || true

systemctl stop apparmor >/dev/null 2>&1 || true
systemctl disable apparmor >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 3. Disable Audit Daemon and Remove Audit Trails (Chapter 4 & 6)
# ------------------------------------------------------------------------------
echo "[+] Disabling auditd and removing audit rules..."
systemctl stop auditd >/dev/null 2>&1 || true
systemctl disable auditd >/dev/null 2>&1 || true
rm -f /etc/audit/rules.d/*.rules >/dev/null 2>&1 || true
auditctl -D >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 4. SSH Server Degradation (Chapter 5)
# ------------------------------------------------------------------------------
echo "[+] Weakening SSH daemon configuration..."
mkdir -p /etc/ssh/sshd_config.d
cat << 'EOF' > /etc/ssh/sshd_config.d/99-cis-degrade.conf
PermitRootLogin yes
PermitEmptyPasswords yes
X11Forwarding yes
MaxAuthTries 10
IgnoreRhosts no
HostbasedAuthentication yes
ClientAliveInterval 0
ClientAliveCountMax 3
LogLevel DEBUG
EOF

# Restart SSH service without breaking active session
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 5. Overly Permissive File Permissions (Chapter 1, 5, 7)
# ------------------------------------------------------------------------------
echo "[+] Weakening file permissions (banners, cron, shadow)..."
chmod 666 /etc/issue /etc/issue.net /etc/motd 2>/dev/null || true
echo "Authorized access only? NO - SYSTEM DEGRADED FOR TESTING" > /etc/issue
echo "Authorized access only? NO - SYSTEM DEGRADED FOR TESTING" > /etc/issue.net

# Cron permissions (world writable)
chmod 666 /etc/crontab 2>/dev/null || true

# Sensitive system files: world-readable shadow
chmod 644 /etc/shadow 2>/dev/null || true
chmod 644 /etc/gshadow 2>/dev/null || true

# Permissive system umask
cat << 'EOF' > /etc/profile.d/99-cis-degrade-umask.sh
umask 000
EOF

# Permissive core dump limits
cat << 'EOF' > /etc/security/limits.d/99-cis-degrade.conf
* hard core unlimited
* soft core unlimited
EOF

# ------------------------------------------------------------------------------
# 6. Password Quality and Age Policies (Chapter 5)
# ------------------------------------------------------------------------------
echo "[+] Degrading password expiration and quality policies..."
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   0/' /etc/login.defs
fi

if [ -f /etc/security/pwquality.conf ]; then
    cat << 'EOF' > /etc/security/pwquality.conf
minlen = 1
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0
EOF
fi

# ------------------------------------------------------------------------------
# 7. Insecure Services and Network Daemons (Chapter 2)
# ------------------------------------------------------------------------------
echo "[+] Enabling insecure legacy services if available..."
# Attempt apt install for banned services non-interactively
DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rpcbind avahi-daemon rsync >/dev/null 2>&1 || true

systemctl enable --now rpcbind >/dev/null 2>&1 || true
systemctl enable --now avahi-daemon >/dev/null 2>&1 || true
systemctl enable --now rsync >/dev/null 2>&1 || true

echo "[✓] Anti-Hardening complete. System is now in a heavily degraded, vulnerable state."
