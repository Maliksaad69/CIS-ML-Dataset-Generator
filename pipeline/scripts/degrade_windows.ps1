# ==============================================================================
# CyberGuard Anti-Hardening Degradation Script (Windows 10 / 11)
# Purpose: Intentionally weakens Windows security configuration to establish a
#          "dirty baseline" with near-zero passed CIS rules for ML training.
# ==============================================================================

Write-Host "[*] Starting CyberGuard Anti-Hardening Degradation for Windows..." -ForegroundColor Yellow

# 1. Disable Windows Defender Protection
Write-Host "[+] Disabling Windows Defender real-time protection..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -ErrorAction SilentlyContinue
} catch {}

# 2. Disable Windows Firewall on all profiles
Write-Host "[+] Disabling Windows Firewall across Domain, Public, and Private..."
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
} catch {}

# 3. Disable User Account Control (UAC)
Write-Host "[+] Disabling User Account Control (UAC)..."
try {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "EnableLUA" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "ConsentPromptBehaviorAdmin" -Value 0 -ErrorAction SilentlyContinue
} catch {}

# 4. Enable Remote Desktop without Network Level Authentication (NLA)
Write-Host "[+] Weakening Remote Desktop (disabling NLA)..."
try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0 -ErrorAction SilentlyContinue
} catch {}

# 5. Weaken Password Policy
Write-Host "[+] Weakening Password Policy (min length 0, infinite age)..."
try {
    net accounts /minpwlen:0 /maxpwage:unlimited /minpwage:0 > $null 2>&1
} catch {}

# 6. Weaken Authentication (Enable NTLMv1 / LM)
Write-Host "[+] Enabling legacy NTLMv1 authentication..."
try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 0 -ErrorAction SilentlyContinue
} catch {}

# 7. Clear Audit Policies
Write-Host "[+] Disabling all security audit logging..."
try {
    auditpol /set /category:* /success:disable /failure:disable > $null 2>&1
} catch {}

# 8. Disable Screen Saver Secure Lock
Write-Host "[+] Disabling secure screen lock..."
try {
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaverIsSecure" -Value "0" -ErrorAction SilentlyContinue
} catch {}

Write-Host "[✓] Windows Anti-Hardening complete. System is now in a heavily degraded, vulnerable state." -ForegroundColor Green
