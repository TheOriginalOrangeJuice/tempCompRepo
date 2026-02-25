#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | awk -F: '{print $6}')"
TARGET_HOME="${TARGET_HOME:-/root}"

find_integrity_runner() {
  if command_exists dpkg; then
    echo "debian"
  elif command_exists rpm; then
    echo "rpm"
  elif command_exists pacman; then
    echo "arch"
  elif command_exists apk; then
    echo "alpine"
  else
    echo "unknown"
  fi
}

start_integrity_check() {
  local mode
  mode="$(find_integrity_runner)"
  local output_file="/root/modified_files.txt"

  case "$mode" in
    debian)
      if ! command_exists debsums; then
        warn "debsums not found. Attempting install."
        install_packages debsums || {
          warn "debsums install failed. Skipping integrity check."
          return 1
        }
      fi
      nohup bash -c "debsums -ac > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    rpm)
      nohup bash -c "rpm -Va | grep -E '^[^ ]*[5MUG]' > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    arch)
      nohup bash -c "pacman -Qkk > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    alpine)
      nohup bash -c "apk verify > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    *)
      warn "No known package integrity check command for this distro."
      return 1
      ;;
  esac

  ok "File integrity check started in background. Output: $output_file (PID: $!)"
}

ensure_locate_tool() {
  if command_exists locate && command_exists updatedb; then
    return 0
  fi

  install_packages plocate || install_packages mlocate || {
    warn "Could not install plocate/mlocate."
    return 1
  }

  return 0
}

scan_suid_guid() {
  local suid_file="/root/suid_files.txt"
  local sgid_file="/root/sgid_files.txt"
  local unexpected_file="/root/suid_unexpected.txt"
  local allow_file="/root/suid_allowlist.txt"

  find / -perm -4000 -type f 2>/dev/null | sort -u | tee "$suid_file"
  find / -perm -2000 -type f 2>/dev/null | sort -u | tee "$sgid_file"

  cat >"$allow_file" <<'ALLOWEOF'
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/lib/openssh/ssh-keysign
ALLOWEOF

  grep -Fxv -f "$allow_file" "$suid_file" >"$unexpected_file" || true

  section_header "Unexpected SUID binaries (review manually)"
  if [[ -s "$unexpected_file" ]]; then
    cat "$unexpected_file"
  else
    ok "No unexpected SUID entries based on current allowlist."
  fi

  info "If needed, remove dangerous SUID bits with: chmod u-x /path/to/exe"
}

section_header "Section 1 - Enumeration"

section_header "1) OS Version, Hostname, IP, Distribution"
hostnamectl || warn "hostnamectl unavailable"
uname -a || warn "uname failed"
cat /etc/os-release || warn "Missing /etc/os-release"
if command_exists ip; then
  ip addr
elif command_exists ifconfig; then
  ifconfig -a
else
  warn "Neither ip nor ifconfig is available."
fi
pause_step

section_header "2) Services and Ports (Screenshot Prompt)"
list_listening_sockets || true
if command_exists lsof; then
  lsof -i -n -P || warn "lsof command failed"
else
  warn "lsof not installed"
fi
info "Take a screenshot of the open ports and network services now."
pause_step

section_header "3) DNS, LDAP, SSSD, Kerberos Checks"
cat /etc/nsswitch.conf || warn "Cannot read /etc/nsswitch.conf"
info "Check if ldap/sss entries exist in nsswitch sources."
if grep -Eq '(^|[[:space:]])sss([[:space:]]|$)' /etc/nsswitch.conf 2>/dev/null; then
  info "sss detected in nsswitch. Printing /etc/sssd/sssd.conf (if present)."
  if [[ -f /etc/sssd/sssd.conf ]]; then
    cat /etc/sssd/sssd.conf
  else
    warn "/etc/sssd/sssd.conf not found"
  fi
fi
if command_exists realm; then
  realm list || warn "realm list failed"
else
  warn "realm command not available"
fi
systemctl --no-pager --full status sssd winbind 2>/dev/null || warn "sssd/winbind services not active or missing"
cat /etc/hosts || warn "Cannot read /etc/hosts"
cat /etc/resolv.conf || warn "Cannot read /etc/resolv.conf"
pause_step

section_header "4) Environment Variables and Bash Config"
alias || true
echo "PATH=$PATH"
if [[ -f "$TARGET_HOME/.bashrc" ]]; then
  cat "$TARGET_HOME/.bashrc"
else
  warn "No .bashrc found for $TARGET_USER at $TARGET_HOME"
fi
if [[ -f "$TARGET_HOME/.bash_history" ]]; then
  cat "$TARGET_HOME/.bash_history"
else
  warn "No .bash_history found for $TARGET_USER at $TARGET_HOME"
fi
pause_step

section_header "5) Enumerate Users and Shell Access"
getent passwd 0 || warn "Could not query UID 0"
if [[ -r /etc/passwd ]]; then
  awk '{
    line=$0
    gsub(/false/,"\033[1;31mfalse\033[0m",line)
    gsub(/nologin/,"\033[1;31mnologin\033[0m",line)
    print line
  }' /etc/passwd
fi
getent group | grep -E '^(wheel|sudo|root):' || warn "wheel/sudo/root group entries not found"
cat /etc/shells || warn "Cannot read /etc/shells"
info "Generally acceptable shells: dash, rbash, sh, bash."
pause_step

section_header "6) Check Sudo Permissions"
if [[ -d /etc/sudoers.d ]]; then
  ls -la /etc/sudoers.d
  find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
    printf '\n----- %s -----\n' "$f"
    cat "$f"
  done
fi
if ask_yes_no "Open visudo now to inspect for unsafe directives (example: !authenticate)?" "N"; then
  if command_exists nano; then
    EDITOR=nano visudo
  else
    visudo
  fi
fi
if [[ -n "${SUDO_USER:-}" ]]; then
  sudo -l -U "$SUDO_USER" || true
else
  sudo -l || true
fi
pause_step

section_header "7) Session/Authentication Context (Screenshot Prompt)"
w || warn "w command failed"
lastb 2>/dev/null | head -n 40 || warn "lastb unavailable (check /var/log/btmp permissions)"
last -i 2>/dev/null | head -n 40 || warn "last -i failed"
info "Take screenshots of w, lastb, and last -i outputs now."
pause_step

section_header "8) Enabled Startup Services"
systemctl list-unit-files --type=service | grep enabled || warn "Could not list enabled services"
pause_step

section_header "9) Running Processes"
ps -efH || warn "ps command failed"
pause_step

section_header "10) Cron Jobs"
while IFS=: read -r user _; do
  printf '\n=== crontab for %s ===\n' "$user"
  crontab -u "$user" -l 2>/dev/null || true
done </etc/passwd

read -r -p "Enter a username to edit crontab now with 'crontab -eu <user>' (blank to skip): " cron_user
if [[ -n "$cron_user" ]]; then
  crontab -u "$cron_user" -e
fi
if ls /etc/cron.d/* >/dev/null 2>&1; then
  cat /etc/cron.d/*
else
  warn "No files in /etc/cron.d/"
fi
pause_step

section_header "11) Save Installed Programs"
if save_installed_packages /root/installed_apps.txt; then
  sed -n '1,200p' /root/installed_apps.txt
  info "Full list is available at /root/installed_apps.txt"
fi
pause_step

section_header "12) Find Files with SUID/SGID"
scan_suid_guid
pause_step

section_header "13) Validate File Integrity in Background"
start_integrity_check || true
pause_step

section_header "14) Install mlocate/plocate and Search for Password Artifacts"
if ensure_locate_tool; then
  updatedb || warn "updatedb failed"
  locate password | head -n 200 || true

  read -r -p "Enter first password keyword to search for (blank to skip grep scan): " pw1
  read -r -p "Enter second password keyword to search for (blank to skip grep scan): " pw2

  if [[ -n "$pw1" && -n "$pw2" ]]; then
    pattern="$(regex_escape "$pw1")|$(regex_escape "$pw2")"
    find /etc /opt /tmp /home /usr /var -type f -print0 2>/dev/null \
      | xargs -0 grep -IinH -E "$pattern" 2>/dev/null \
      | tee /root/password_pattern_hits.txt || true
    info "Password pattern hits saved to /root/password_pattern_hits.txt"
  else
    warn "Skipping pattern grep because both keywords were not provided."
  fi
fi
pause_step

section_header "15) Find World-Writable Files and Directories"
find / -xdev -type f -perm -0002 -print 2>/dev/null | tee /root/world_writable_files.txt
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | tee /root/world_writable_dirs_no_sticky.txt
pause_step

section_header "16) Check File Mounts"
cat /etc/fstab || warn "Cannot read /etc/fstab"
pause_step

section_header "17) Review /tmp and /opt Contents"
find /tmp /opt -mindepth 1 -maxdepth 2 -ls 2>/dev/null | sed -n '1,300p'
pause_step

section_header "18) Locate SSH Keys"
if command_exists locate; then
  locate authorized_keys || true
  locate id_rsa || true
else
  warn "locate not available"
fi
pause_step

section_header "19) Change Root Password"
if ask_yes_no "Run 'passwd root' now?" "Y"; then
  passwd root
else
  warn "Skipped root password change."
fi
pause_step

section_header "20) Add Root SSH Public Key"
read -r -p "Paste the public key to append to /root/.ssh/authorized_keys (blank to skip): " root_pubkey
if [[ -n "$root_pubkey" ]]; then
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  touch /root/.ssh/authorized_keys
  if command_exists lsattr && command_exists chattr; then
    if lsattr /root/.ssh/authorized_keys 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      chattr -i /root/.ssh/authorized_keys || true
    fi
  fi

  if grep -Fxq "$root_pubkey" /root/.ssh/authorized_keys; then
    info "Key already exists in authorized_keys"
  else
    printf '%s\n' "$root_pubkey" >>/root/.ssh/authorized_keys
    ok "Key appended"
  fi

  chmod 600 /root/.ssh/authorized_keys
  if command_exists chattr; then
    chattr +i /root/.ssh/authorized_keys || warn "Could not set immutable bit on authorized_keys"
  fi
else
  warn "No key supplied. Skipping authorized_keys update."
fi
pause_step

section_header "21) Manual Validation Prompt"
info "Test SSH connectivity in a separate terminal now before continuing."
pause_step

section_header "22) Move Key Binaries (High-Risk)"
warn "Moving sudo/chattr can lock out normal administration paths."
if ask_yes_no "Proceed with moving chattr and sudo binaries to /root/.wow_bin_*?" "N"; then
  chattr_path="$(command -v chattr || true)"
  sudo_path="$(command -v sudo || true)"

  if [[ -n "$chattr_path" && -x "$chattr_path" ]]; then
    mv "$chattr_path" /root/.wow_bin_c
    ok "Moved $chattr_path -> /root/.wow_bin_c"
  else
    warn "chattr binary not found"
  fi

  if [[ -n "$sudo_path" && -x "$sudo_path" ]]; then
    mv "$sudo_path" /root/.wow_bin_s
    ok "Moved $sudo_path -> /root/.wow_bin_s"
  else
    warn "sudo binary not found"
  fi
else
  info "Skipped moving sudo/chattr binaries."
fi
pause_step

ok "Section 1 complete."
