#!/usr/bin/env bash
set -euo pipefail

RED() { printf "%s\n" "$*" | sed 's/\x1b\[[0-9;]*m//g'; }

section() { printf "\n== %s ==\n" "$1"; }
kv() { printf "%-22s %s\n" "$1" "$2"; }

need() { command -v "$1" >/dev/null 2>&1; }

sudo_if() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

section "BASIC"
kv "Timestamp" "$(date -Is)"
kv "Hostname" "$(hostnamectl --static 2>/dev/null || hostname)"
kv "Uptime" "$(uptime -p 2>/dev/null || true)"
kv "OS" "$( ( . /etc/os-release; echo "$PRETTY_NAME" ) 2>/dev/null || true )"
kv "Kernel" "$(uname -srmo)"
kv "Virtualization" "$(systemd-detect-virt 2>/dev/null || echo unknown)"
kv "Timezone" "$(timedatectl show -p Timezone --value 2>/dev/null || true)"

section "CPU & LOAD (topline)"
if need lscpu; then
  kv "CPU" "$(lscpu | awk -F: '
    $1~/(Model name)/{gsub(/^ +/,"",$2); mn=$2}
    $1~/(CPU\(s\))/ && !c {gsub(/^ +/,"",$2); c=$2}
    END{print mn " | vCPU=" c}'
  )"
fi
kv "Load avg" "$(cut -d' ' -f1-3 /proc/loadavg)"
kv "Top CPU procs" "$(ps -eo comm,pcpu --sort=-pcpu | awk 'NR==1{next} NR<=6{printf "%s(%.1f%%) ",$1,$2} END{print ""}')"

section "MEMORY"
kv "Mem+Swap" "$(free -h | awk 'NR==2{m=$2"/"$3} NR==3{s=$2"/"$3} END{print "Mem used/total="m" | Swap used/total="s}')"
kv "Top RSS procs" "$(ps -eo comm,rss --sort=-rss | awk 'NR==1{next} NR<=6{printf "%s(%.0fMB) ",$1,$2/1024} END{print ""}')"
kv "OOM kills (boot)" "$(journalctl -k -b 0 --no-pager 2>/dev/null | grep -E "Out of memory|Killed process" | tail -n 2 | wc -l | tr -d ' ')"

section "DISK & FS"
kv "Block devs" "$(lsblk -dn -o NAME,SIZE,TYPE | awk '{printf "%s:%s:%s ",$1,$2,$3} END{print ""}')"
kv "Root FS" "$(df -hPT / | awk 'NR==2{print $1" "$2" used="$5" mount="$7}')"
kv "Inodes /" "$(df -ih / | awk 'NR==2{print "used="$5" ("$3"/"$2")"}')"
kv "FSTAB entries" "$(grep -vE '^\s*#|^\s*$' /etc/fstab 2>/dev/null | wc -l | tr -d ' ')"
kv "Big dirs /var" "$(du -xsh /var/* 2>/dev/null | sort -h | tail -n 5 | awk '{printf "%s:%s ",$2,$1} END{print ""}')"

section "NETWORK (compact)"
kv "IPs" "$(ip -brief addr 2>/dev/null | awk '{print $1"="$3}' | tr '\n' ' ' | sed 's/  */ /g')"
kv "Routes" "$(ip route 2>/dev/null | head -n 4 | tr '\n' '; ')"
kv "Resolvers" "$( (resolvectl dns 2>/dev/null || cat /etc/resolv.conf 2>/dev/null) | head -n 6 | tr '\n' '; ' )"
kv "Listening ports" "$(sudo_if ss -H -lntup | awk '{print $1":"$5"("$7")"}' | sed 's/.*://;s/users:(("\([^"]*\)".*/\1/' | head -n 12 | tr '\n' ' ' | sed 's/  */ /g')"

section "SECURITY QUICKLOOK"
# SSH
if [ -f /etc/ssh/sshd_config ] || [ -d /etc/ssh/sshd_config.d ]; then
  SSH_PORT="$(sudo_if sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || echo "?")"
  kv "SSH port" "$SSH_PORT"
  kv "PermitRootLogin" "$(sudo_if sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}' || echo "?")"
  kv "PasswordAuth" "$(sudo_if sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2; exit}' || echo "?")"
fi

# Firewall
if need ufw; then
  kv "UFW" "$(sudo_if ufw status 2>/dev/null | head -n 2 | tr '\n' '; ')"
fi
if need nft; then
  kv "nft ruleset" "$(sudo_if nft list ruleset 2>/dev/null | wc -l | tr -d ' ') lines"
fi

# Recent auth failures (very compact)
AUTHLOG="/var/log/auth.log"
if [ -f "$AUTHLOG" ]; then
  kv "Auth fail (24h)" "$(sudo_if awk -v d="$(date -d '24 hours ago' '+%b %e %H:%M:%S')" '
    BEGIN{c=0}
    $0 ~ /Failed password|Invalid user/ {c++}
    END{print c}' "$AUTHLOG" 2>/dev/null || echo "?")"
fi

section "SERVICES"
kv "Enabled services" "$(systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | awk 'NR>1 && $1 ~ /\.service$/ {c++} END{print c+0}')"
kv "Failed units" "$(systemctl --failed --no-pager 2>/dev/null | awk 'NR>1 && NF{c++} END{print c+0}')"
kv "Top active (10)" "$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | awk 'NR>1 && $1 ~ /\.service$/ {print $1}' | head -n 10 | tr '\n' ' ')"

section "PACKAGES & UPDATES"
kv "APT upgrades" "$( (sudo_if apt-get -s upgrade 2>/dev/null || true) | awk '/^Inst /{c++} END{print c+0}')"
kv "Unattended-upg" "$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo no)"
kv "Reboot req" "$( [ -f /var/run/reboot-required ] && echo yes || echo no )"

section "USERS / ACCESS (compact)"
kv "Users (uid>=1000)" "$(awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd | tr '\n' ' ')"
kv "Sudoers (group)" "$(getent group sudo | awk -F: '{print $4}' 2>/dev/null || echo "")"
kv "Root keys" "$(sudo_if ls -1 /root/.ssh/authorized_keys 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
kv "Login banners" "$( (test -f /etc/issue && head -n1 /etc/issue || echo none) | tr -d '\n')"

section "CRON / TIMERS (signals)"
kv "Cron jobs" "$(sudo_if find /etc/cron.* /var/spool/cron/crontabs -type f 2>/dev/null | wc -l | tr -d ' ')"
kv "Systemd timers" "$(systemctl list-timers --all --no-pager 2>/dev/null | awk 'NR>1 && NF{c++} END{print c+0}')"

section "CONTAINERS (if any)"
if need docker; then
  kv "Docker" "$(docker --version 2>/dev/null || true)"
  kv "Docker ps" "$(sudo_if docker ps --format '{{.Names}}' 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"
else
  kv "Docker" "not installed"
fi
if need podman; then kv "Podman" "$(podman --version 2>/dev/null || true)"; fi
if need snap; then kv "Snap pkgs" "$(snap list 2>/dev/null | awk 'NR>1{c++} END{print c+0}')"; fi

section "KERNEL / SYSCTL (few key knobs)"
kv "swappiness" "$(sysctl -n vm.swappiness 2>/dev/null || echo "?")"
kv "fs.file-max" "$(sysctl -n fs.file-max 2>/dev/null || echo "?")"
kv "somaxconn" "$(sysctl -n net.core.somaxconn 2>/dev/null || echo "?")"

section "DONE"
echo "Tip: Share this output. If you want it even shorter: bash discovery.sh | sed -n '1,140p'"
