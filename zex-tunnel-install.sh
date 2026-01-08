#!/usr/bin/env bash
set -euo pipefail

# =========================================================
#          ZEX Tunnel V3 — Installer (No API)
#          Repo layout expected:
#           ./Waterwall
#           ./web.py
#           ./web.zex (optional)
#           ./config/core.json
#           ./config/config_ir.json
#           ./config/config_kharej.json
#           ./zex-tunnel-install.sh
# =========================================================

VERSION="V3.250908"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
BASE_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
CFG_DIR="${BASE_DIR}/config"
PANEL_PATH="/usr/local/bin/zt"
INSTALL_SCRIPT_PATH="${BASE_DIR}/zex-tunnel-install.sh"

# Services (ONLY these)
SERVICE_TUN="zextunnel"
SERVICE_WEB="zexweb"

# Binaries / app files
BIN_TUN="${BASE_DIR}/Waterwall"
BIN_WEB="${BASE_DIR}/web.py"

# Generated / mutable runtime files
CORE_MAIN="${BASE_DIR}/core.json"
CONF_IR_MAIN="${BASE_DIR}/config_ir.json"
CONF_KH_MAIN="${BASE_DIR}/config_kharej.json"
CONF_ZEX_MAIN="${BASE_DIR}/config.zex"
WEB_ZEX_MAIN="${BASE_DIR}/web.zex"

# Templates (must exist)
CORE_SRC="${CFG_DIR}/core.json"
CONF_IR_SRC="${CFG_DIR}/config_ir.json"
CONF_KH_SRC="${CFG_DIR}/config_kharej.json"

# -------------------- Logging (alongside script) --------------------
LOG_FILE="${BASE_DIR}/install-$(date +'%Y%m%d-%H%M%S').log"
if ! ( : >"$LOG_FILE" ) 2>/dev/null; then
  LOG_FILE="/tmp/zex-tunnel-install-$(date +'%Y%m%d-%H%M%S').log"
  : >"$LOG_FILE"
fi
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo "ZEX Tunnel installer started at: $(date -Is)"
echo "Version: $VERSION"
echo "Base dir: $BASE_DIR"
echo "Log file: $LOG_FILE"
echo "User: $(id -u)  Host: $(hostname)"
echo "===================================================="

trap 'rc=$?;
  echo "!! ERROR: exit_code=$rc at line=$LINENO command: $BASH_COMMAND";
  echo "Log file: $LOG_FILE";
  exit $rc' ERR

if [[ "${TRACE:-0}" == "1" ]]; then
  set -x
  export PS4="+ [${BASH_SOURCE##*/}:${LINENO}] "
fi
# -------------------- End Logging --------------------

# -------------------- Helpers --------------------
die(){ echo "ERROR: $*" >&2; exit 1; }
warn(){ echo "Warning: $*" >&2; }
info(){ echo "[INFO] $*"; }

clr(){ printf "\e[%sm%b\e[0m" "$1" "$2"; }
banner(){
  clear
  clr "36;1" "====================================================\n"
  clr "37;1" "                 ZEX Tunnel V3 Setup\n"
  clr "36;1" "====================================================\n\n"
}

require_root(){
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root: sudo bash $SCRIPT_PATH"
}

check_ubuntu(){
  local ver=""
  if [[ -r /etc/os-release ]]; then
    ver="$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')"
  fi
  case "$ver" in
    20.04|22.04|20.*|22.*) : ;;
    *) die "Unsupported Ubuntu VERSION_ID=${ver:-unknown} (supported: 20.x, 22.x)" ;;
  esac
}

require_cmd(){
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

require_file(){
  [[ -f "$1" ]] || die "Missing required file: $1"
}

# robust input: always try /dev/tty so it works even if stdin is redirected
TTY_IN=""
init_tty(){
  if [[ -r /dev/tty ]]; then
    TTY_IN="/dev/tty"
  else
    TTY_IN="" # no tty available
  fi
}

read_tty(){
  # usage: read_tty "Prompt" varname [silent=0|1]
  local prompt="$1"; local __var="$2"; local silent="${3:-0}"
  local val=""
  if [[ -n "$TTY_IN" ]]; then
    if [[ "$silent" == "1" ]]; then
      IFS= read -r -s -p "$prompt" val <"$TTY_IN" || return 1
      echo >&2
    else
      IFS= read -r -p "$prompt" val <"$TTY_IN" || return 1
    fi
  else
    # no tty: do NOT pretend this works; fail clearly
    return 2
  fi
  printf -v "$__var" '%s' "$val"
  return 0
}

press_enter(){
  local _tmp=""
  if read_tty "Press Enter to continue... " _tmp 0; then :; else :; fi
}

# -------------------- Networking helpers --------------------
get_local_ipv4(){
  ip -4 addr show scope global up 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}
get_local_ipv6(){
  ip -6 addr show scope global up 2>/dev/null | awk '/inet6/{print $2}' | cut -d/ -f1 | grep -v '^fe80:' | head -n1
}

# -------------------- Dependencies --------------------
install_deps(){
  info "Installing dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-pip unzip wget curl jq
  pip3 install -U flask flask-socketio eventlet psutil
}

# -------------------- Validation --------------------
validate_domain_ip(){
  local s="$1"
  [[ -n "$s" ]] || return 1
  [[ "$s" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1
  [[ ${#s} -le 253 ]] || return 1
  return 0
}

validate_protocol(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p>=0 && p<=255 )) || return 1
  return 0
}

validate_ports(){
  local ports_str="$1"
  [[ -n "$ports_str" ]] || return 1
  local -A seen=()
  local p count=0
  for p in $ports_str; do
    ((count++))
    (( count <= 10 )) || return 1
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p>=1 && p<=65535 )) || return 1
    [[ -z "${seen[$p]:-}" ]] || return 1
    seen[$p]=1
  done
  return 0
}

# -------------------- Config templating --------------------
apply_placeholders_ir(){
  local iran_ip="$1" kh_ip="$2" proto="$3" first_port="$4"
  sed -i -e "s#__IP_IRAN__#${iran_ip}#g" \
         -e "s#__IP_KHAREJ__#${kh_ip}#g" \
         -e "s#__PROTOCOL__#${proto}#g" \
         -e "s#__PORT__#${first_port}#g" "$CONF_IR_MAIN"
}

apply_placeholders_kh(){
  local iran_ip="$1" kh_ip="$2" proto="$3"
  sed -i -e "s#__IP_IRAN__#${iran_ip}#g" \
         -e "s#__IP_KHAREJ__#${kh_ip}#g" \
         -e "s#__PROTOCOL__#${proto}#g" "$CONF_KH_MAIN"
}

add_extra_ports_to_ir_json(){
  local json_file="$CONF_IR_MAIN"
  local ports_str="$1"

  local first=true
  local extras=() p
  for p in $ports_str; do
    if $first; then first=false; continue; fi
    extras+=("$p")
  done
  [[ ${#extras[@]} -eq 0 ]] && return 0

  local ports_json
  ports_json="$(printf '%s\n' "${extras[@]}" | jq -R . | jq -s .)"

  local jq_prog='
    def mk_input(n; port):
      {name: ("input"+(n|tostring)), type:"TcpListener",
       settings:{address:"0.0.0.0", port:(port|tonumber), nodelay:true},
       next: ("output"+(n|tostring))};
    def mk_output(n; port):
      {name: ("output"+(n|tostring)), type:"TcpConnector",
       settings:{nodelay:true, address:"10.10.0.2", port:(port|tonumber)}};

    ([ .nodes[]? | select(.name|startswith("input")) ] | length) as $base
    | reduce ( $ports | to_entries[] ) as $e
        ( .;
          .nodes += [
            mk_input(($base + $e.index + 1); $e.value),
            mk_output(($base + $e.index + 1); $e.value)
          ]
        )'

  local tmpf
  tmpf="$(mktemp)"
  jq --argjson ports "$ports_json" "$jq_prog" "$json_file" > "$tmpf"
  mv "$tmpf" "$json_file"
}

# -------------------- systemd units --------------------
write_units(){
  cat >/etc/systemd/system/${SERVICE_TUN}.service <<EOF
[Unit]
Description=ZEX Tunnel (Waterwall)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStart=$BIN_TUN
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/${SERVICE_WEB}.service <<EOF
[Unit]
Description=ZEX Tunnel Web
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStart=/usr/bin/python3 $BIN_WEB
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_TUN}" "${SERVICE_WEB}" >/dev/null 2>&1 || true
}

# -------------------- Panel (zt) --------------------
write_panel(){
  cat >"$PANEL_PATH" <<EOS
#!/usr/bin/env bash
set -euo pipefail

VERSION="$VERSION"
BASE_DIR="$BASE_DIR"
PANEL_NAME="ZEX Tunnel V3 — Panel"

SERVICE_TUN="zextunnel"
SERVICE_WEB="zexweb"

CONFIG_FILE="\$BASE_DIR/config.zex"
WEB_CONFIG="\$BASE_DIR/web.zex"
CORE_MAIN="\$BASE_DIR/core.json"
INSTALLER="\$BASE_DIR/zex-tunnel-install.sh"

CLR(){ printf "\\e[%sm%b\\e[0m" "\$1" "\$2"; }
LINE(){ printf "%s\\n" "---------------------------------------------------------------------"; }
HDR(){
  clear
  CLR "36;1" "=====================================================================\\n"
  CLR "37;1" "                        \${PANEL_NAME}\\n"
  CLR "36;1" "=====================================================================\\n\\n"
}

get_location() {
  if [[ -f "\$CORE_MAIN" ]]; then
    local cfg
    cfg=\$(jq -r '.configs[0]' "\$CORE_MAIN" 2>/dev/null || echo "")
    if [[ "\$cfg" == "config_ir.json" ]]; then
      echo "Iran"; return
    elif [[ "\$cfg" == "config_kharej.json" ]]; then
      echo "Kharej"; return
    fi
  fi
  echo "Unknown"
}

main_loop() {
  while true; do
    HDR
    local IRAN_IP="N/A" KHAREJ_IP="N/A" PROT="N/A" PORTS="N/A"
    if [[ -f "\$CONFIG_FILE" ]]; then
      mapfile -t cfg < "\$CONFIG_FILE" || true
      IRAN_IP="\${cfg[0]:-N/A}"
      KHAREJ_IP="\${cfg[1]:-N/A}"
      PROT="\${cfg[2]:-N/A}"
      PORTS="\${cfg[3]:-N/A}"
    fi

    local LOC; LOC=\$(get_location)
    systemctl is-active --quiet "\${SERVICE_TUN}" && ST_TUN=\$(CLR 32 "ACTIVE") || ST_TUN=\$(CLR 31 "INACTIVE")
    systemctl is-active --quiet "\${SERVICE_WEB}" && ST_WEB=\$(CLR 32 "ACTIVE") || ST_WEB=\$(CLR 31 "INACTIVE")

    printf "  Server Information\\n"
    LINE
    printf "   Location          : %s\\n" "\$LOC"
    printf "   IRAN IP/Domain    : %s\\n" "\$IRAN_IP"
    printf "   Kharej IP/Domain  : %s\\n" "\$KHAREJ_IP"
    printf "   Protocol Number   : %s\\n" "\$PROT"
    printf "   Tunnel Ports      : %s\\n" "\$PORTS"
    printf "   Active Config     : %s\\n\\n" "\$( [[ -f "\$CORE_MAIN" ]] && jq -r '.configs[0]' "\$CORE_MAIN" || echo "N/A" )"

    printf "  Service Status\\n"
    LINE
    printf "   %s (Main)  : %b    | Exec: %s\\n" "\$SERVICE_TUN" "\$ST_TUN" "\$BASE_DIR/Waterwall"
    printf "   %s (Web)   : %b    | Exec: %s\\n\\n" "\$SERVICE_WEB" "\$ST_WEB" "/usr/bin/python3 \$BASE_DIR/web.py"

    printf "  Web API\\n"
    LINE
    local WEB_PORT="N/A" WEB_PASS="N/A"
    if [[ -f "\$WEB_CONFIG" ]]; then
      mapfile -t wcfg < "\$WEB_CONFIG" || true
      WEB_PORT="\${wcfg[0]:-N/A}"
      WEB_PASS="\${wcfg[2]:-N/A}"
    fi
    printf "   Port              : %s\\n" "\$WEB_PORT"
    printf "   Login Password    : %s\\n" "\$WEB_PASS"
    printf "   Config File       : %s\\n\\n" "\$WEB_CONFIG"

    CLR "36;1" "=====================================================================\\n"
    printf "  Actions\\n"
    CLR "36;1" "=====================================================================\\n\\n"

    printf "  Tunnel Controls\\n"
    LINE
    printf "   1) Start %s\\n" "\$SERVICE_TUN"
    printf "   2) Stop  %s\\n" "\$SERVICE_TUN"
    printf "   3) Restart %s\\n" "\$SERVICE_TUN"
    printf "   4) View %s logs\\n" "\$SERVICE_TUN"
    printf "   5) Kill all Waterwall processes\\n\\n"

    printf "  Web Controls\\n"
    LINE
    printf "   6) Start %s\\n" "\$SERVICE_WEB"
    printf "   7) Stop  %s\\n" "\$SERVICE_WEB"
    printf "   8) Restart %s\\n" "\$SERVICE_WEB"
    printf "   9) View %s logs\\n\\n" "\$SERVICE_WEB"

    printf "  Configuration\\n"
    LINE
    printf "   10) Reconfigure Tunnel\\n"
    printf "   11) Edit Web Config\\n\\n"

    printf "  System / Maintenance\\n"
    LINE
    printf "   16) Uninstall Everything\\n"
    printf "   17) Install Sanaei Xray Panel\\n"
    printf "   18) Reboot Server\\n\\n"

    LINE
    printf "  Shortcuts: [Enter] Refresh   [Q] Quit\\n"
    LINE
    printf "\\nSelect an option > "
    read -r opt || exit 0

    case "\$opt" in
      1) systemctl start "\$SERVICE_TUN" ;;
      2) systemctl stop "\$SERVICE_TUN" ;;
      3) systemctl restart "\$SERVICE_TUN" ;;
      4) journalctl -u "\$SERVICE_TUN" -n 200 --no-pager | \${PAGER:-less} ;;
      5) pkill -f "\$BASE_DIR/Waterwall" || true ;;
      6) systemctl start "\$SERVICE_WEB" ;;
      7) systemctl stop  "\$SERVICE_WEB" ;;
      8) systemctl restart "\$SERVICE_WEB" ;;
      9) journalctl -u "\$SERVICE_WEB" -n 200 --no-pager | \${PAGER:-less} ;;
      10)
         if [[ -x "\$INSTALLER" ]]; then
           sudo bash "\$INSTALLER" --reconfigure
         else
           echo "Installer not found: \$INSTALLER"
         fi
         read -r -p "Press Enter..." _ ;;
      11)
         read -r -p "New Web Port: " nport
         read -r -p "New Web Password: " npass
         if [[ -f "\$WEB_CONFIG" ]]; then
           mapfile -t arr < "\$WEB_CONFIG"
           arr[0]="\$nport"
           arr[2]="\$npass"
           printf '%s\\n%s\\n%s\\n%s\\n' "\${arr[0]}" "\${arr[1]:-}" "\${arr[2]}" "\${arr[3]:-}" > "\$WEB_CONFIG"
           echo "Web config updated."
           systemctl restart "\$SERVICE_WEB"
         else
           echo "web.zex not found."
         fi
         read -r -p "Press Enter..." _ ;;
      16)
         echo "You are about to uninstall ZEX Tunnel V3 and remove all services/files."
         read -r -p "Step 1 — Confirm (Y/N): " ans
         [[ "\${ans,,}" == "y" ]] || { echo "Cancelled."; read -r -p "Enter..." _; continue; }
         read -r -p "Step 2 — Type 'UNINSTALL' to proceed: " tok
         [[ "\$tok" == "UNINSTALL" ]] || { echo "Token mismatch. Cancelled."; read -r -p "Enter..." _; continue; }

         systemctl disable --now zextunnel zexweb || true
         rm -f /etc/systemd/system/zextunnel.service /etc/systemd/system/zexweb.service || true
         systemctl daemon-reload
         rm -rf "\$BASE_DIR"
         rm -f /usr/local/bin/zt
         echo "Uninstall complete. A reboot is recommended."
         exit 0
         ;;
      17) bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh) ; exit 0 ;;
      18) echo "Rebooting..." ; sleep 1 ; reboot ;;
      q|Q|0) exit 0 ;;
      "") : ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

main_loop
EOS

  chmod +x "$PANEL_PATH"
}

# -------------------- Wizard --------------------
run_wizard(){
  banner

  local ipv4 ipv6
  ipv4="$(get_local_ipv4)"; [[ -z "${ipv4:-}" ]] && ipv4="N/A"
  ipv6="$(get_local_ipv6)"; [[ -z "${ipv6:-}" ]] && ipv6="N/A"
  echo "IP V4: $ipv4"
  echo "IP V6: $ipv6"
  echo "---------------------------------------"
  echo "Mode: choose server location"
  echo "  [1] Iran"
  echo "  [2] Kharej"
  echo

  local location_choice=""
  if ! read_tty "> " location_choice 0; then
    die "No interactive TTY available. Run this script in a real terminal (not via non-interactive execution)."
  fi

  case "$location_choice" in
    1|2) : ;;
    *) die "Invalid selection." ;;
  esac

  echo
  local iran_ip="" kharej_ip="" protocol="" ports=""

  read_tty "IRAN IP/Domain: " iran_ip 0 || die "Input failed."
  validate_domain_ip "$iran_ip" || die "Invalid IRAN IP/Domain."

  read_tty "Kharej IP/Domain: " kharej_ip 0 || die "Input failed."
  validate_domain_ip "$kharej_ip" || die "Invalid Kharej IP/Domain."

  echo
  if [[ "$location_choice" == "1" ]]; then
    echo "Protocol Number (Default 18)"
    echo "Tip: Using a protocol number below 100 is recommended."
  else
    echo "Protocol Number (Default 18)"
    echo "Note: Enter the same protocol number used on the Iran server."
    echo "Tip: Using a protocol number below 100 is recommended."
  fi

  read_tty "> " protocol 0 || die "Input failed."
  [[ -z "${protocol:-}" ]] && protocol=18
  validate_protocol "$protocol" || die "Invalid protocol number (0-255)."

  if [[ "$location_choice" == "1" ]]; then
    echo
    echo "Port Number(s)"
    echo "- Single-port: enter one port (e.g., 443)"
    echo "- Multi-port : enter space-separated ports (e.g., 443 2083 2087)"
    read_tty "> " ports 0 || die "Input failed."
    [[ -z "${ports:-}" ]] && ports="443"
    validate_ports "$ports" || die "Invalid port list (1-10 ports, unique, 1-65535)."
  else
    ports=""
  fi

  echo
  echo "----------------------------------------------------"
  echo "Review & Confirm"
  echo "  IRAN IP/Domain   : $iran_ip"
  echo "  Kharej IP/Domain : $kharej_ip"
  echo "  Protocol Number  : $protocol"
  if [[ "$location_choice" == "1" ]]; then
    echo "  Port Number(s)   : $ports"
  else
    echo "  Port Number(s)   : (N/A in Kharej mode)"
  fi
  echo "----------------------------------------------------"

  local go=""
  read_tty "Proceed? (Y/n): " go 0 || die "Input failed."
  [[ -z "${go:-}" || "${go,,}" == "y" ]] || die "Cancelled."

  # Always write config.zex
  printf '%s\n%s\n%s\n%s\n' "$iran_ip" "$kharej_ip" "$protocol" "${ports:-}" > "$CONF_ZEX_MAIN"

  if [[ "$location_choice" == "1" ]]; then
    cp -f "$CORE_SRC" "$CORE_MAIN"
    sed -i -e 's#"__CONFIG_FILE__"#"config_ir.json"#g' "$CORE_MAIN"
    cp -f "$CONF_IR_SRC" "$CONF_IR_MAIN"

    local first_port
    first_port="${ports%% *}"
    apply_placeholders_ir "$iran_ip" "$kharej_ip" "$protocol" "$first_port"
    add_extra_ports_to_ir_json "$ports"
  else
    cp -f "$CORE_SRC" "$CORE_MAIN"
    sed -i -e 's#"__CONFIG_FILE__"#"config_kharej.json"#g' "$CORE_MAIN"
    cp -f "$CONF_KH_SRC" "$CONF_KH_MAIN"
    apply_placeholders_kh "$iran_ip" "$kharej_ip" "$protocol"
  fi
}

# -------------------- Reconfigure --------------------
reconfigure_flow(){
  info "Temporarily disabling services..."
  systemctl disable --now "${SERVICE_TUN}" "${SERVICE_WEB}" >/dev/null 2>&1 || true

  info "Cleaning old main configs..."
  rm -f "$CORE_MAIN" "$CONF_IR_MAIN" "$CONF_KH_MAIN" "$CONF_ZEX_MAIN"

  run_wizard

  info "Re-enabling and restarting services..."
  systemctl enable "${SERVICE_TUN}" "${SERVICE_WEB}" >/dev/null 2>&1 || true
  systemctl restart "${SERVICE_TUN}" "${SERVICE_WEB}" || true
}

# -------------------- Main --------------------
main(){
  require_root
  check_ubuntu
  init_tty

  require_cmd ip
  require_cmd sed
  require_cmd jq
  require_cmd systemctl
  require_cmd python3
  require_cmd pip3

  # Ensure templates exist (repo layout)
  require_file "$CORE_SRC"
  require_file "$CONF_IR_SRC"
  require_file "$CONF_KH_SRC"

  # Ensure installer is at expected path for panel usage
  if [[ "$SCRIPT_PATH" != "$INSTALL_SCRIPT_PATH" ]]; then
    info "Copying installer to: $INSTALL_SCRIPT_PATH"
    cp -f "$SCRIPT_PATH" "$INSTALL_SCRIPT_PATH"
    chmod +x "$INSTALL_SCRIPT_PATH"
  else
    chmod +x "$INSTALL_SCRIPT_PATH" || true
  fi

  if [[ "${1:-}" == "--reconfigure" ]]; then
    reconfigure_flow
    info "Done. Log: $LOG_FILE"
    exit 0
  fi

  install_deps
  write_units
  write_panel

  # Keep original behavior: warn if binaries not present yet (do not abort)
  [[ -f "$BIN_TUN" ]] || warn "Expected file not found yet: $BIN_TUN"
  [[ -f "$BIN_WEB" ]] || warn "Expected file not found yet: $BIN_WEB"

  run_wizard

  chmod +x "$BIN_TUN" 2>/dev/null || true

  systemctl restart "${SERVICE_TUN}" "${SERVICE_WEB}" || true
  systemctl enable  "${SERVICE_TUN}" "${SERVICE_WEB}" >/dev/null 2>&1 || true

  echo
  info "Installation complete. Run 'zt' to open the panel."
  info "Log saved at: $LOG_FILE"
}

main "$@"
