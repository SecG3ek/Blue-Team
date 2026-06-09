#!/usr/bin/env bash
#
# SilkTrail DFIR - Linux Edition
# ---------------------------
# Incident-response triage collector for Linux hosts. This is the Linux port of a
# Windows PowerShell DFIR script. It gathers volatile and persistent forensic
# artifacts into a timestamped directory under /tmp and archives the result for
# easy collection (e.g. SIEM import / offline analysis).
#
# Output:  /tmp/DFIR-<hostname>-<YYYY-MM-DD>/
# Archive: /tmp/DFIR-<hostname>-<YYYY-MM-DD>.tar.gz
#
# Run as root for the full set of artifacts (system logs, all-user histories,
# btmp/lastb, samba/nfs state, SUID sweep). Without root it collects everything
# the current user can read.
#
# Usage:  ./SilkTrail-dfir-linux.sh [-w DAYS]
#           -w DAYS   Search window in days for time-bounded log collection (default: 1)
#
# NOTE: This script only READS and COPIES artifacts. It makes no changes to the
# host other than writing its own output under /tmp.

# Best-effort collector: do NOT abort on individual command failures.
set -u

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
cat <<'BANNER'
  ____  _ _ _    _____          _ _    ____  _____ ___ ____  
 / ___|(_) | | _|_   _| __ __ _(_) |  |  _ \|  ___|_ _|  _ \ 
 \___ \| | | |/ / | || '__/ _` | | |  | | | | |_   | || |_) |
  ___) | | |   <  | || | | (_| | | |  | |_| |  _|  | ||  _ < 
 |____/|_|_|_|\_\ |_||_|  \__,_|_|_|  |____/|_|   |___|_| \_\
                                                                        
                                                           Linux Edition

BANNER

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
SW=1
while [ $# -gt 0 ]; do
    case "$1" in
        -w|--window) SW="${2:-1}"; shift 2 ;;
        -h|--help)
            grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
case "$SW" in (*[!0-9]*|'') echo "Search window must be an integer (days)." >&2; exit 1 ;; esac

# ---------------------------------------------------------------------------
# Environment / paths
# ---------------------------------------------------------------------------
TS="$(date +%Y-%m-%d)"
HOST="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
BASE="/tmp/DFIR-${HOST}-${TS}"
CSVDIR="${BASE}/CSV-Results-SIEM-Import-Data"
LOGFILE="${BASE}/collection.log"

# The user we treat as "current user" for per-user artefacts. If invoked via
# sudo, this is the real user behind the sudo, not root.
TARGET_USER="${SUDO_USER:-$(id -un 2>/dev/null)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
[ -z "$TARGET_HOME" ] && TARGET_HOME="$HOME"

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1

mkdir -p "$BASE" "$CSVDIR" 2>/dev/null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOGFILE"; }

# CSV-escape a single field (wrap in quotes, double internal quotes, strip CR/LF)
csv_field() {
    local f="$1"
    f="${f//$'\r'/ }"
    f="${f//$'\n'/ }"
    f="${f//\"/\"\"}"
    printf '"%s"' "$f"
}

# csv_row field1 field2 ... -> properly quoted CSV line
csv_row() {
    local out="" first=1 a
    for a in "$@"; do
        if [ $first -eq 1 ]; then out="$(csv_field "$a")"; first=0
        else out="${out},$(csv_field "$a")"; fi
    done
    printf '%s\n' "$out"
}

# copy a file/dir into the output tree, preserving attributes, best-effort
collect_path() {
    local src="$1" dst="$2"
    [ -e "$src" ] || return 0
    mkdir -p "$(dirname "$dst")" 2>/dev/null
    cp -a --no-preserve=ownership "$src" "$dst" 2>>"$LOGFILE" || cp -a "$src" "$dst" 2>>"$LOGFILE"
}

# ===========================================================================
# Collection functions
# ===========================================================================

# --- Network configuration (Get-IPInfo) -----------------------------------
get_ipinfo() {
    local txt="${BASE}/ipinfo.txt"
    {
        echo "===== Interfaces / addresses ====="
        if have ip; then ip addr show; else have ifconfig && ifconfig -a; fi
        echo; echo "===== Routing table ====="
        if have ip; then ip route show; ip -6 route show; else have route && route -n; fi
        echo; echo "===== ARP / neighbour cache ====="
        if have ip; then ip neigh show; else have arp && arp -an; fi
    } >"$txt" 2>>"$LOGFILE"

    local csv="${CSVDIR}/IPConfiguration.csv"
    csv_row "Interface" "Family" "Address" >"$csv"
    if have ip; then
        ip -o addr show 2>/dev/null | awk '{print $2","$3","$4}' | while IFS=, read -r ifc fam addr; do
            csv_row "$ifc" "$fam" "$addr"
        done >>"$csv"
    fi
    log "Collected network configuration"
}

# --- Established connections (Get-OpenConnections) -------------------------
get_open_connections() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/OpenConnections.txt"
    if have ss; then ss -tnp state established >"$txt" 2>>"$LOGFILE"
    elif have netstat; then netstat -tnp 2>/dev/null | grep ESTABLISHED >"$txt"; fi

    local csv="${CSVDIR}/OpenTCPConnections.csv"
    csv_row "LocalAddress" "PeerAddress" "Process" >"$csv"
    if have ss; then
        ss -tnpH state established 2>/dev/null | while read -r _ _ _ local peer proc; do
            csv_row "$local" "$peer" "$proc"
        done >>"$csv"
    fi
    log "Collected established connections"
}

# --- Listening sockets (bonus, high-value for DFIR) ------------------------
get_listening_ports() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/ListeningPorts.txt"
    if have ss; then ss -tulnp >"$txt" 2>>"$LOGFILE"
    elif have netstat; then netstat -tulnp >"$txt" 2>>"$LOGFILE"; fi

    local csv="${CSVDIR}/ListeningPorts.csv"
    csv_row "Proto" "LocalAddress" "Process" >"$csv"
    if have ss; then
        ss -tulnpH 2>/dev/null | while read -r proto _ _ _ local _ proc; do
            csv_row "$proto" "$local" "$proc"
        done >>"$csv"
    fi
    log "Collected listening sockets"
}

# --- Persistence / autoruns (Get-AutoRunInfo) ------------------------------
get_autoruns() {
    local dir="${BASE}/Persistence"; mkdir -p "$dir"
    local txt="${dir}/AutoRunInfo.txt"
    {
        echo "===== systemd enabled unit files ====="
        have systemctl && systemctl list-unit-files --state=enabled --no-pager 2>/dev/null
        echo; echo "===== rc.local / init scripts ====="
        [ -f /etc/rc.local ] && { echo "--- /etc/rc.local ---"; cat /etc/rc.local; }
        ls -la /etc/init.d 2>/dev/null
        echo; echo "===== Shell profile / login scripts ====="
        for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
            [ -f "$f" ] && echo "--- $f ---" && cat "$f"
        done
        echo; echo "===== Desktop autostart ====="
        ls -la /etc/xdg/autostart 2>/dev/null
        [ -d "${TARGET_HOME}/.config/autostart" ] && ls -la "${TARGET_HOME}/.config/autostart"
        echo; echo "===== ld.so.preload (library hijack persistence) ====="
        [ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload || echo "(empty / not present)"
    } >"$txt" 2>>"$LOGFILE"

    # Copy the actual files for offline review
    collect_path /etc/rc.local           "${dir}/files/etc/rc.local"
    collect_path /etc/ld.so.preload      "${dir}/files/etc/ld.so.preload"
    collect_path /etc/xdg/autostart      "${dir}/files/etc/xdg/autostart"
    [ -d "${TARGET_HOME}/.config/autostart" ] && collect_path "${TARGET_HOME}/.config/autostart" "${dir}/files/user-autostart"
    log "Collected autorun / persistence locations"
}

# --- Kernel modules (Get-InstalledDrivers analog) --------------------------
get_kernel_modules() {
    local dir="${BASE}/Persistence"; mkdir -p "$dir"
    local txt="${dir}/KernelModules.txt"
    { have lsmod && lsmod; echo; echo "===== /proc/modules ====="; cat /proc/modules 2>/dev/null; } >"$txt" 2>>"$LOGFILE"

    local csv="${CSVDIR}/KernelModules.csv"
    csv_row "Module" "Size" "UsedByCount" "UsedBy" >"$csv"
    if have lsmod; then
        lsmod 2>/dev/null | tail -n +2 | while read -r mod size cnt used; do
            csv_row "$mod" "$size" "$cnt" "$used"
        done >>"$csv"
    fi
    log "Collected kernel modules"
}

# --- Logged-in / active users (Get-ActiveUsers) ----------------------------
get_active_users() {
    local dir="${BASE}/UserInformation"; mkdir -p "$dir"
    local txt="${dir}/ActiveUsers.txt"
    { echo "===== who ====="; who -a 2>/dev/null; echo; echo "===== w ====="; w 2>/dev/null; \
      echo; echo "===== last 50 logins ====="; have last && last -n 50 2>/dev/null; } >"$txt" 2>>"$LOGFILE"

    local csv="${CSVDIR}/ActiveUsers.csv"
    csv_row "User" "TTY" "LoginTime" "From" >"$csv"
    who 2>/dev/null | while read -r u tty rest; do
        local from; from="$(echo "$rest" | grep -oE '\(.*\)' | tr -d '()')"
        local t; t="$(echo "$rest" | sed -E 's/ *\(.*\)//')"
        csv_row "$u" "$tty" "$t" "$from"
    done >>"$csv"
    log "Collected active/logged-in users"
}

# --- Local users (Get-LocalUsers) ------------------------------------------
get_local_users() {
    local dir="${BASE}/UserInformation"; mkdir -p "$dir"
    local txt="${dir}/LocalUsers.txt"
    {
        echo "===== /etc/passwd ====="; cat /etc/passwd 2>/dev/null
        echo; echo "===== /etc/group ====="; cat /etc/group 2>/dev/null
        echo; echo "===== sudo / wheel / admin group members ====="
        for g in sudo wheel admin root; do getent group "$g" 2>/dev/null; done
        echo; echo "===== UID 0 accounts (should normally be 'root' only) ====="
        awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
        echo; echo "===== Accounts with login shells ====="
        awk -F: '$7!~"(nologin|false)$"{print $1" -> "$7}' /etc/passwd 2>/dev/null
    } >"$txt" 2>>"$LOGFILE"

    local csv="${CSVDIR}/LocalUsers.csv"
    csv_row "User" "UID" "GID" "Home" "Shell" >"$csv"
    while IFS=: read -r u _ uid gid _ home shell; do
        csv_row "$u" "$uid" "$gid" "$home" "$shell"
    done < /etc/passwd >>"$csv" 2>>"$LOGFILE"
    log "Collected local user accounts"
}

# --- Processes with executable hashes (Get-ActiveProcesses) ----------------
get_processes() {
    local dir="${BASE}/ProcessInformation"; mkdir -p "$dir"
    have ps && ps auxww >"${dir}/ProcessList.txt" 2>>"$LOGFILE"
    if have ps; then ps -eo pid,ppid,user,stat,start,etime,cmd --forest >"${dir}/ProcessTree.txt" 2>>"$LOGFILE"; fi

    local csv="${CSVDIR}/Processes.csv"
    local uniqcsv="${dir}/UniqueProcessHash.csv"
    csv_row "PID" "PPID" "User" "Name" "ExePath" "SHA256" "CommandLine" >"$csv"
    csv_row "ExePath" "SHA256" >"$uniqcsv"

    local seen="${dir}/.seen_hashes"; : >"$seen"
    local pid
    for pid in /proc/[0-9]*; do
        pid="${pid#/proc/}"
        [ -d "/proc/$pid" ] || continue
        local comm cmd exe sha ppid uid user
        comm="$(cat "/proc/$pid/comm" 2>/dev/null)"
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        [ -z "$cmd" ] && cmd="[$comm]"   # kernel thread
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"   # plain readlink: empty for kernel threads
        ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
        uid="$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null)"
        user="$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)"; [ -z "$user" ] && user="$uid"
        sha=""
        if [ -n "$exe" ] && [ -f "$exe" ]; then
            sha="$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')"
            if [ -n "$sha" ] && ! grep -q "^$sha$" "$seen" 2>/dev/null; then
                echo "$sha" >>"$seen"
                csv_row "$exe" "$sha" >>"$uniqcsv"
            fi
        fi
        csv_row "$pid" "$ppid" "$user" "$comm" "$exe" "$sha" "$cmd" >>"$csv"
    done
    rm -f "$seen"
    log "Collected running processes (with SHA-256 of executables)"
}

# --- Running services (Get-RunningServices) --------------------------------
get_running_services() {
    local dir="${BASE}/Services"; mkdir -p "$dir"
    local txt="${dir}/RunningServices.txt"
    if have systemctl; then
        systemctl list-units --type=service --state=running --no-pager >"$txt" 2>>"$LOGFILE"
    elif have service; then
        service --status-all >"$txt" 2>>"$LOGFILE"
    fi
    local csv="${CSVDIR}/RunningServices.csv"
    csv_row "Unit" "Load" "Active" "Sub" "Description" >"$csv"
    if have systemctl; then
        systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null \
          | while read -r unit load active sub desc; do
                csv_row "$unit" "$load" "$active" "$sub" "$desc"
            done >>"$csv"
    fi
    log "Collected running services"
}

# --- Scheduled tasks: cron + systemd timers + at (Get-ScheduledTasks) ------
get_scheduled_tasks() {
    local dir="${BASE}/ScheduledTasks"; mkdir -p "$dir"
    local txt="${dir}/ScheduledTasks.txt"
    {
        echo "===== System crontab (/etc/crontab) ====="; cat /etc/crontab 2>/dev/null
        echo; echo "===== /etc/cron.d ====="; for f in /etc/cron.d/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done
        echo; echo "===== /etc/cron.{hourly,daily,weekly,monthly} ====="
        ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
        echo; echo "===== Per-user crontabs (/var/spool/cron) ====="
        for d in /var/spool/cron /var/spool/cron/crontabs; do
            [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done
        done
        echo; echo "===== at jobs ====="; have atq && atq 2>/dev/null
        echo; echo "===== systemd timers ====="; have systemctl && systemctl list-timers --all --no-pager 2>/dev/null
    } >"$txt" 2>>"$LOGFILE"

    # copy cron files for offline review
    collect_path /etc/crontab "${dir}/files/etc/crontab"
    collect_path /etc/cron.d  "${dir}/files/etc/cron.d"
    for d in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$d" ] && collect_path "$d" "${dir}/files/spool-cron"
    done

    local csv="${CSVDIR}/SystemdTimers.csv"
    csv_row "Next" "Left" "Last" "Passed" "Unit" "Activates" >"$csv"
    if have systemctl; then
        systemctl list-timers --all --no-pager --no-legend 2>/dev/null \
          | while read -r nd nt ntz left lastd lastt _ passed unit activates; do
                csv_row "$nd $nt $ntz" "$left" "$lastd $lastt" "$passed" "$unit" "$activates"
            done >>"$csv"
    fi
    log "Collected scheduled tasks (cron / timers / at)"
}

# --- Mounted / network shares (Get-NetworkShares) --------------------------
get_network_shares() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/NetworkShares.txt"
    {
        echo "===== mount ====="; mount 2>/dev/null
        echo; echo "===== /proc/mounts ====="; cat /proc/mounts 2>/dev/null
        echo; echo "===== /etc/fstab ====="; cat /etc/fstab 2>/dev/null
    } >"$txt" 2>>"$LOGFILE"

    local csv="${CSVDIR}/NetworkShares.csv"
    csv_row "Source" "MountPoint" "FSType" "Options" >"$csv"
    awk '$3 ~ /(nfs|nfs4|cifs|smbfs|smb3|fuse.sshfs|9p)/ {print}' /proc/mounts 2>/dev/null \
      | while read -r src mnt fs opts _; do csv_row "$src" "$mnt" "$fs" "$opts"; done >>"$csv"
    log "Collected mounts / network shares"
}

# --- SMB / NFS exports (Get-SMBShares) -------------------------------------
get_smb_shares() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/SMBShares.txt"
    {
        echo "===== Samba config (/etc/samba/smb.conf) ====="; cat /etc/samba/smb.conf 2>/dev/null
        echo; echo "===== net usershare ====="; have net && net usershare info --long 2>/dev/null
        echo; echo "===== smbstatus (requires root) ====="; have smbstatus && smbstatus 2>/dev/null
        echo; echo "===== NFS exports (/etc/exports) ====="; cat /etc/exports 2>/dev/null
        echo; echo "===== exportfs -v ====="; have exportfs && exportfs -v 2>/dev/null
        echo; echo "===== showmount -e localhost ====="; have showmount && showmount -e localhost 2>/dev/null
    } >"$txt" 2>>"$LOGFILE"
    log "Collected SMB/NFS share configuration"
}

# --- Remote sessions (Get-RDPSessions analog) ------------------------------
get_remote_sessions() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/RemoteSessions.txt"
    {
        echo "===== loginctl sessions ====="
        if have loginctl; then
            loginctl list-sessions --no-pager 2>/dev/null
            echo
            loginctl list-sessions --no-legend --no-pager 2>/dev/null | awk '{print $1}' | while read -r s; do
                [ -n "$s" ] && { echo "--- session $s ---"; loginctl show-session "$s" 2>/dev/null; echo; }
            done
        fi
        echo "===== Remote (pts) logins from 'who' ====="; who 2>/dev/null | grep -E '\(' 
    } >"$txt" 2>>"$LOGFILE"
    log "Collected remote/interactive sessions"
}

# --- DNS resolution state (Get-DNSCache analog) ----------------------------
get_dns_cache() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    local txt="${dir}/DNSCache.txt"
    {
        echo "Note: Linux does not keep a system-wide queryable DNS cache like Windows."
        echo "Capturing resolver configuration and any resolver-daemon state instead."
        echo; echo "===== /etc/resolv.conf ====="; cat /etc/resolv.conf 2>/dev/null
        echo; echo "===== /etc/hosts ====="; cat /etc/hosts 2>/dev/null
        echo; echo "===== /etc/nsswitch.conf ====="; cat /etc/nsswitch.conf 2>/dev/null
        echo; echo "===== systemd-resolved statistics ====="; have resolvectl && resolvectl statistics 2>/dev/null
        echo; echo "===== systemd-resolved status ====="; have resolvectl && resolvectl status 2>/dev/null
        echo; echo "===== nscd stats ====="; have nscd && nscd -g 2>/dev/null
    } >"$txt" 2>>"$LOGFILE"
    log "Collected DNS resolver state"
}

# --- Shell history, current user (Get-PowershellHistoryCurrentUser) --------
get_history_current_user() {
    local dir="${BASE}/ShellHistory/${TARGET_USER}"; mkdir -p "$dir"
    for f in .bash_history .zsh_history .sh_history .ash_history .python_history .mysql_history .psql_history; do
        collect_path "${TARGET_HOME}/${f}" "${dir}/${f}"
    done
    [ -f "${TARGET_HOME}/.local/share/fish/fish_history" ] && \
        collect_path "${TARGET_HOME}/.local/share/fish/fish_history" "${dir}/fish_history"
    log "Collected shell history for ${TARGET_USER}"
}

# --- Recently installed software (Get-RecentlyInstalledSoftwareEventLogs) --
get_recent_software() {
    local dir="${BASE}/Applications"; mkdir -p "$dir"
    local txt="${dir}/RecentlyInstalledSoftware.txt"
    {
        if have dpkg-query; then
            echo "===== dpkg: packages installed in last ${SW} day(s) (from /var/log/dpkg.log) ====="
            for lf in /var/log/dpkg.log /var/log/dpkg.log.1; do
                [ -f "$lf" ] && grep " install \| status installed " "$lf" 2>/dev/null
            done | awk -v cutoff="$(date -d "-${SW} days" +%Y-%m-%d 2>/dev/null)" '$1 >= cutoff'
            echo; echo "===== apt history ====="
            cat /var/log/apt/history.log 2>/dev/null
        fi
        if have rpm; then
            echo "===== rpm: packages by install date (most recent first) ====="
            rpm -qa --last 2>/dev/null | head -n 100
        fi
        echo; echo "===== Full installed package inventory saved separately ====="
    } >"$txt" 2>>"$LOGFILE"

    # full inventory
    have dpkg-query && dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' >"${dir}/InstalledPackages.txt" 2>>"$LOGFILE"
    have rpm && rpm -qa >"${dir}/InstalledPackages.txt" 2>>"$LOGFILE"
    log "Collected recently installed software"
}

# --- Connected devices (Get-ConnectedDevices) ------------------------------
get_connected_devices() {
    local dir="${BASE}/ConnectedDevices"; mkdir -p "$dir"
    local txt="${dir}/ConnectedDevices.txt"
    {
        echo "===== USB (lsusb) ====="; have lsusb && lsusb
        echo; echo "===== PCI (lspci) ====="; have lspci && lspci
        echo; echo "===== Block devices (lsblk) ====="; have lsblk && lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL 2>/dev/null
        echo; echo "===== Recent USB/storage events from kernel ring buffer ====="
        have dmesg && dmesg 2>/dev/null | grep -iE 'usb|sd[a-z]|mmc|new .* device' | tail -n 100
    } >"$txt" 2>>"$LOGFILE"
    log "Collected connected devices"
}

# --- Chromium-family browser artefacts (Get-ChromiumFiles) -----------------
# $1 = username, $2 = home dir
collect_chromium_for() {
    local user="$1" home="$2"
    local base="${BASE}/Browsers/Chromium/${user}"
    local root prof
    for root in "${home}/.config/google-chrome" "${home}/.config/chromium" \
                "${home}/.config/microsoft-edge" "${home}/.config/BraveSoftware/Brave-Browser" \
                "${home}/.config/vivaldi" "${home}/.config/opera"; do
        [ -d "$root" ] || continue
        for prof in "$root"/*/; do
            [ -d "$prof" ] || continue
            local name; name="$(basename "$prof")"
            [ -f "${prof}History" ]     && collect_path "${prof}History"     "${base}/$(basename "$root")/${name}/History"
            [ -f "${prof}Preferences" ] && collect_path "${prof}Preferences" "${base}/$(basename "$root")/${name}/Preferences"
            [ -f "${prof}Web Data" ]    && collect_path "${prof}Web Data"    "${base}/$(basename "$root")/${name}/WebData"
        done
    done
}

# --- Firefox browser artefacts (Get-FirefoxFiles) --------------------------
collect_firefox_for() {
    local user="$1" home="$2"
    local profroot="${home}/.mozilla/firefox"
    [ -d "$profroot" ] || return 0
    local base="${BASE}/Browsers/Firefox/${user}"
    local prof
    for prof in "$profroot"/*/; do
        [ -d "$prof" ] || continue
        local name; name="$(basename "$prof")"
        for f in places.sqlite permissions.sqlite content-prefs.sqlite cookies.sqlite extensions.json; do
            [ -f "${prof}${f}" ] && collect_path "${prof}${f}" "${base}/${name}/${f}"
        done
        [ -d "${prof}extensions" ] && collect_path "${prof}extensions" "${base}/${name}/extensions"
    done
}

get_browser_current_user() {
    collect_chromium_for "$TARGET_USER" "$TARGET_HOME"
    collect_firefox_for  "$TARGET_USER" "$TARGET_HOME"
    log "Collected browser artefacts for ${TARGET_USER}"
}

# --- Security posture (Get-DefenderExclusions analog) ----------------------
get_security_posture() {
    local dir="${BASE}/SecurityPosture"; mkdir -p "$dir"
    {
        echo "===== SELinux ====="; have getenforce && getenforce; have sestatus && sestatus 2>/dev/null
        echo; echo "===== AppArmor ====="; have aa-status && aa-status 2>/dev/null
        echo; echo "===== Firewall: ufw ====="; have ufw && ufw status verbose 2>/dev/null
        echo; echo "===== Firewall: nftables ====="; have nft && nft list ruleset 2>/dev/null
        echo; echo "===== Firewall: iptables ====="; have iptables && iptables -S 2>/dev/null
        echo; echo "===== Firewall: ip6tables ====="; have ip6tables && ip6tables -S 2>/dev/null
    } >"${dir}/SecurityPosture.txt" 2>>"$LOGFILE"
    log "Collected security posture (SELinux/AppArmor/firewall)"
}

# ============================ ROOT-ONLY =====================================

# --- Auth/security events within window (Get-SecurityEvents) ---------------
get_security_events() {
    local dir="${BASE}/SecurityEvents"; mkdir -p "$dir"
    local txt="${dir}/SecurityEvents.txt"
    local cnt="${dir}/EventCount.txt"

    if have journalctl; then
        journalctl --since "-${SW} days" --no-pager 2>/dev/null \
            | grep -iE 'sshd|sudo|su\[|polkit|pam|authentication|login|useradd|usermod|passwd' >"$txt"
    fi
    # also capture raw auth logs
    for lf in /var/log/auth.log /var/log/secure; do
        [ -f "$lf" ] && { echo "===== $lf ====="; cat "$lf"; } >>"$txt" 2>>"$LOGFILE"
    done

    {
        echo "===== Authentication event counts (last ${SW} day(s)) ====="
        printf '%-28s %s\n' "Failed password:"      "$(grep -c 'Failed password'        "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "Accepted password:"    "$(grep -c 'Accepted password'      "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "Accepted publickey:"   "$(grep -c 'Accepted publickey'     "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "Invalid user:"         "$(grep -c 'Invalid user'           "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "sudo commands:"        "$(grep -c 'sudo:.*COMMAND='        "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "session opened:"       "$(grep -c 'session opened'         "$txt" 2>/dev/null)"
        printf '%-28s %s\n' "authentication failure:" "$(grep -c 'authentication failure' "$txt" 2>/dev/null)"
    } >"$cnt"
    log "Collected security/auth events (window ${SW}d)"
}

# --- Copy system logs (Get-EventViewerFiles analog) ------------------------
get_system_logs() {
    local dir="${BASE}/Logs"; mkdir -p "$dir"
    for lf in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages \
              /var/log/kern.log /var/log/dpkg.log /var/log/yum.log /var/log/dnf.log \
              /var/log/audit/audit.log /var/log/faillog /var/log/cron /var/log/boot.log; do
        collect_path "$lf" "${dir}/$(echo "$lf" | sed 's#^/##; s#/#_#g')"
    done
    # binary login databases
    collect_path /var/log/wtmp "${dir}/wtmp"
    collect_path /var/log/btmp "${dir}/btmp"
    collect_path /var/run/utmp "${dir}/utmp"
    # journald (export recent window in a portable form)
    if have journalctl; then
        journalctl --since "-${SW} days" --no-pager >"${dir}/journal-last-${SW}d.txt" 2>>"$LOGFILE"
    fi
    log "Copied system logs"
}

# --- Failed logins (root) --------------------------------------------------
get_failed_logins() {
    local dir="${BASE}/UserInformation"; mkdir -p "$dir"
    { echo "===== lastb (failed logins) ====="; have lastb && lastb -n 100 2>/dev/null; \
      echo; echo "===== lastlog (per-account last login) ====="; have lastlog && lastlog 2>/dev/null; \
    } >"${dir}/FailedLogins.txt" 2>>"$LOGFILE"
    log "Collected failed-login records"
}

# --- All-users shell history (Get-PowershellConsoleHistory-AllUsers) -------
get_history_all_users() {
    local f u home
    getent passwd 2>/dev/null | while IFS=: read -r u _ uid _ _ home _; do
        [ -d "$home" ] || continue
        case "$home" in /home/*|/root) ;; *) continue ;; esac
        local dir="${BASE}/ShellHistory/${u}"; mkdir -p "$dir"
        for f in .bash_history .zsh_history .sh_history .ash_history .python_history .mysql_history .psql_history; do
            [ -f "${home}/${f}" ] && collect_path "${home}/${f}" "${dir}/${f}"
        done
        [ -f "${home}/.local/share/fish/fish_history" ] && \
            collect_path "${home}/.local/share/fish/fish_history" "${dir}/fish_history"
    done
    log "Collected shell history for all users"
}

# --- All-users browser artefacts (root) ------------------------------------
get_browser_all_users() {
    local u home
    getent passwd 2>/dev/null | while IFS=: read -r u _ uid _ _ home _; do
        [ -d "$home" ] || continue
        case "$home" in /home/*|/root) ;; *) continue ;; esac
        collect_chromium_for "$u" "$home"
        collect_firefox_for  "$u" "$home"
    done
    log "Collected browser artefacts for all users"
}

# --- Remotely opened files via Samba/NFS (Get-RemotelyOpenedFiles) ---------
get_remote_open_files() {
    local dir="${BASE}/Connections"; mkdir -p "$dir"
    { echo "===== smbstatus open files ====="; have smbstatus && smbstatus -L 2>/dev/null
      echo; echo "===== lsof on network filesystems ====="
      have lsof && lsof -N 2>/dev/null
      echo; echo "===== NFS server activity (nfsstat) ====="; have nfsstat && nfsstat -o all 2>/dev/null
    } >"${dir}/RemotelyOpenedFiles.txt" 2>>"$LOGFILE"
    log "Collected remotely opened files"
}

# --- SUID/SGID sweep (privilege-escalation persistence) --------------------
get_suid_sgid() {
    local dir="${BASE}/Persistence"; mkdir -p "$dir"
    local txt="${dir}/SUID_SGID_Files.txt"
    echo "SUID/SGID files (search bounded to local filesystems with -xdev):" >"$txt"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
        | while read -r f; do ls -la "$f" 2>/dev/null; done >>"$txt"
    log "Collected SUID/SGID inventory"
}

# --- LVM/Btrfs snapshots (Get-ShadowCopies analog) -------------------------
get_snapshots() {
    local dir="${BASE}/Snapshots"; mkdir -p "$dir"
    { echo "===== LVM logical volumes / snapshots ====="; have lvs && lvs -o +lv_attr,origin 2>/dev/null
      echo; echo "===== LVM snapshots only ====="; have lvscan && lvscan 2>/dev/null
      echo; echo "===== Btrfs subvolumes (if root fs is btrfs) ====="; have btrfs && btrfs subvolume list / 2>/dev/null
    } >"${dir}/Snapshots.txt" 2>>"$LOGFILE"
    log "Collected LVM/Btrfs snapshot information"
}

# ===========================================================================
# Orchestration
# ===========================================================================
run_without_root() {
    get_ipinfo
    get_open_connections
    get_listening_ports
    get_autoruns
    get_kernel_modules
    get_active_users
    get_local_users
    get_processes
    get_running_services
    get_scheduled_tasks
    get_network_shares
    get_smb_shares
    get_remote_sessions
    get_dns_cache
    get_history_current_user
    get_recent_software
    get_connected_devices
    get_browser_current_user
    get_security_posture
    get_snapshots
}

run_with_root() {
    get_security_events
    get_system_logs
    get_failed_logins
    get_history_all_users
    get_browser_all_users
    get_remote_open_files
    get_suid_sgid
}

generate_manifest() {
    log "Generating SHA-256 manifest of collected artefacts"
    ( cd "$BASE" && find . -type f ! -name 'SHA256SUMS' -print0 \
        | xargs -0 sha256sum 2>/dev/null > SHA256SUMS )
}

archive_results() {
    local name; name="$(basename "$BASE")"
    if tar -czf "${BASE}.tar.gz" -C /tmp "$name" 2>>"$LOGFILE"; then
        log "Archive created: ${BASE}.tar.gz"
    fi
    if have zip; then
        ( cd /tmp && zip -rq "${name}.zip" "$name" ) && log "Archive created: ${BASE}.zip"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "SilkTrail DFIR (Linux) starting"
log "Host=${HOST}  TargetUser=${TARGET_USER}  Root=${IS_ROOT}  Window=${SW}d"
log "Output: ${BASE}"

run_without_root
if [ "$IS_ROOT" -eq 1 ]; then
    run_with_root
else
    log "Not running as root - skipping privileged collection (system logs, all-user history, btmp, samba/nfs, SUID sweep). Re-run with sudo for full coverage."
fi

generate_manifest
archive_results

log "Collection complete."
echo
echo "Output directory : ${BASE}"
echo "Archive          : ${BASE}.tar.gz"
